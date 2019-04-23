# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types
import os
import string
import subprocess

class ExampleSwitch13(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
		super(ExampleSwitch13,self).__init__(*args,**kwargs)
		#inicializa a tabela de enderecos mac
		self.mac_to_port = {}
		
		#inicializa a tabela de roteamento
		self.fw_table = {}
		#inicializa a tabela arp
		self.hw_addr = '0a:e4:1c:d1:3e:44'
		self.dst_mac = 'da:f7:a6:8e:95:d4'
		self.netmask = '255.255.255.0'
		self.arp_table = {}
		self.ip_router = ""
		self.ports_hosts_s1 = []
		self.ports_hosts_s2 = []
		self.ports_hosts_s3 = []
		self.ip_switches = {}
		self.all_ports_s1 = []
		self.all_ports_s2 = []
		self.all_ports_s3 = []

	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		msg = ev.msg
		# install the table-miss flow entry.
		self.send_port_stats_request(datapath)
		match = parser.OFPMatch()
		actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
		self.add_flow(datapath, 0, match, actions)

	#Adiciona um flow na tabela de flows do Switch OpenFlow
	def add_flow(self, datapath, priority, match, actions):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		# construct flow_mod message and send it.
		inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
		mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
		datapath.send_msg(mod) 

	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def _packet_in_handler(self, ev):		
		msg = ev.msg
		#body = ev.msg.body
		port = msg.match['in_port']
		in_port = msg.match['in_port']
		datapath = msg.datapath		
		dpid = datapath.id
		self.ip_switches.setdefault(dpid, {})
		try:
			cmd = "ip -4 addr show s"+ str(datapath.id) + "| grep -oP '(?<=inet\s)\d+(\.\d+){3}'"
			resultado = os.popen(cmd).readlines()
			ip_router = resultado[0].rstrip()
			if ip_router not in self.ip_switches[dpid]:
				self.ip_switches[dpid]['ip'] = ip_router
		except:
			return
		
		#analisa o pacote recebido usando a biblioteca de pacotes
		pkt = packet.Packet(msg.data)
		eth_pkt = pkt.get_protocol(ethernet.ethernet)
		pkt_icmp = pkt.get_protocol(icmp.icmp)
		pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
		
		#define o valor padrao para o dicionario
		if not eth_pkt:
			self.logger.info('Not eth')
			return
		if pkt_icmp:
			self.logger.info("ICMP packet in %s src: %s, dst: %s, port: %s", datapath.id, pkt_ipv4.src, pkt_ipv4.dst, in_port)

			self._handle_icmp(datapath, port, eth_pkt, pkt_ipv4, pkt_icmp, pkt)
			return

		if pkt_ipv4:
			self.logger.info('ipv4')
			return		
		pkt_arp = pkt.get_protocol(arp.arp)
		if pkt_arp:
			self.logger.info("ARP packet in %s src: %s, dst: %s, port: %s", datapath.id, eth_pkt.src, eth_pkt.dst, in_port)			
			if(dpid==1):
				if in_port not in self.ports_hosts_s1:
					self.ports_hosts_s1.append(in_port)
					#self.logger.info(self.ports_hosts_s1)
			elif(dpid==2):
				if in_port not in self.ports_hosts_s2:
					self.ports_hosts_s2.append(in_port)
			else:
				if in_port not in self.ports_hosts_s3:
					self.ports_hosts_s3.append(in_port)

			self._handle_arp(msg, datapath, port, eth_pkt, pkt_arp)
			return
	"""
	Processa os pacotes arp
	"""
	def _handle_arp(self, msg, datapath, in_port, eth_pkt, pkt_arp):
		self.logger.info('Ping')
		pkt_src_ip = pkt_arp.src_ip
		pkt_dst_ip = pkt_arp.dst_ip
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		#pega o ID do Datapath para identificar os switches do OpenFlow
		dpid = datapath.id
		self.mac_to_port.setdefault(dpid, {})
		self.arp_table.setdefault(dpid, {})
		dst = eth_pkt.dst
		src = eth_pkt.src
		self.logger.info(self.ip_switches)
		self.logger.info(pkt_dst_ip)
		if pkt_dst_ip == self.ip_switches[dpid]['ip']:
			self.arp_table[dpid][pkt_arp.src_ip] = in_port
			#CRIAR PACOTE ARP REPLY E ENVIAR PARA A PORTA DE ENTRADA

			pkt = packet.Packet()
			pkt.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype, dst=eth_pkt.src, src=self.hw_addr))
			
			pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=self.hw_addr, src_ip=self.ip_switches[dpid]['ip'], dst_mac=pkt_arp.src_mac, dst_ip=pkt_arp.src_ip))
			#self.logger.info(pkt)

			out_port = in_port
			actions = [parser.OFPActionOutput (port=out_port)]
			match = parser.OFPMatch(in_port=in_port, eth_dst=eth_pkt.src)
			self.add_flow(datapath, 1, match, actions)
			self._send_packet(datapath, in_port, pkt)
	
		else:
			#self.logger.info('Encaminhar pacote %s',pkt_arp)
			if self.same_subnet(pkt_src_ip,pkt_dst_ip,self.netmask):
				#FAZER BROADCAST SOMENTE NOS HOSTS
				self.logger.info('Fazer broadcast')
			else:

				#retorna um arp_reply
				self.logger.info('Retornar arp reply')
				pkt = packet.Packet()
				pkt.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype, dst=eth_pkt.src, src=self.hw_addr))
			
				pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=self.hw_addr, src_ip=self.ip_switches[dpid]['ip'], dst_mac=pkt_arp.src_mac, dst_ip=pkt_arp.src_ip))
				#self.logger.info(pkt)

				out_port = in_port
				actions = [parser.OFPActionOutput (port=out_port)]
				match = parser.OFPMatch(in_port=in_port, eth_dst=eth_pkt.src)
				self.add_flow(datapath, 1, match, actions)
				self._send_packet(datapath, in_port, pkt)

				#encaminha o pacote icmp_request para outro switch



			
			#ENVIAR PACOTE PARA OUTRAS PORTAS HOSTS

		"""
			#se for o primeiro pacote
			if in_port not in self.arp_table[dpid]:
				self.arp_table[dpid][pkt_src_ip] = in_port			
				
			#self.logger.info('Arp table: %s', self.arp_table)
			if pkt_arp.opcode == arp.ARP_REPLY:
				#self.logger.info('ARP REPLY src: %s dst: %s', pkt_src_ip, pkt_dst_ip)

				if pkt_dst_ip in self.arp_table[dpid]:
					out_port = self.arp_table[dpid][pkt_dst_ip]		
			

			#aprende o endereco mac para evitar o FLOOD da proxima vez
			self.mac_to_port[dpid][src] = in_port
					
			#se o endereco de mac destino ja foi aprendido
			#decide para qual porta de saida enviar o pacote, de outra forma realiza FLOOD
						
			#self.logger.info('pkt_dst_ip: %s', pkt_dst_ip)
			if pkt_dst_ip in self.arp_table[dpid]:
				out_port = self.arp_table[dpid][pkt_dst_ip]
			else:
				#self.logger.info('Enviar todas as portas')
				out_port = ofproto.OFPP_ALL

			actions = [parser.OFPActionOutput (out_port)]

			if out_port != ofproto.OFPP_ALL:
				#self.logger.info('Match in_port: %s - %s', in_port, pkt_dst_ip)
				if pkt_arp.opcode == arp.ARP_REPLY:
					match = parser.OFPMatch(in_port=out_port, eth_dst=dst)
				else:
					match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
				self.add_flow(datapath, 1, match, actions)
				
			out = parser.OFPPacketOut(datapath=datapath, 
									buffer_id=ofproto.OFP_NO_BUFFER,
									in_port=in_port, 
									actions=actions,
									data=msg.data)		
			
			datapath.send_msg(out)"""
		
	def _handle_icmp(self, datapath, port, pkt_eth, pkt_ipv4, pkt_icmp, pkt_orig):
		dst = pkt_eth.dst
		src = pkt_eth.dst
		dpid = datapath.id
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		self.logger.info('pkt ethernet %s',pkt_eth.src)
		self.logger.info('pkt ipv4: %s, %s', pkt_ipv4.src, pkt_ipv4.proto)
		self.logger.info('dst: %s', pkt_ipv4.dst)
		if pkt_ipv4.dst == self.ip_switches[dpid]['ip']:

			#Sout_port = in_port
			actions = [parser.OFPActionOutput (port=ofproto.OFPP_CONTROLLER)]

			pkt = packet.Packet()
			
			pkt.add_protocol(ethernet.ethernet(ethertype=pkt_eth.ethertype,dst=pkt_eth.src,src=self.hw_addr))

			pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,src=self.ip_switches[dpid]['ip'],proto=pkt_ipv4.proto, option=None))

			pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,code=icmp.ICMP_ECHO_REPLY_CODE,csum=0,data=pkt_icmp.data))
			
			
			match = parser.OFPMatch(in_port=port, eth_type=ether_types.ETH_TYPE_IP, ipv4_dst = pkt_ipv4.dst)
			self.add_flow(datapath, 2, match, actions)
		
		
		self._send_packet(datapath,port,pkt)
			
		"""
		if pkt_ipv4.dst in self.arp_table[dpid]:			
			porta_saida = self.arp_table[dpid][pkt_ipv4.dst]
			
		if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
			self.logger.info('ICMP echo reply')
			return
		
		
		pkt = packet.Packet()
		pkt.add_protocol(ethernet.ethernet(ethertype=pkt_eth.ethertype, dst=pkt_eth.dst, src=pkt_eth.src))
		pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.dst, src=pkt_ipv4.dst, proto=pkt_ipv4.proto))
		pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=pkt_icmp.data))
		actions = [parser.OFPActionOutput (porta_saida)]
		match = parser.OFPMatch(in_port=porta_saida, eth_dst=dst)
		self.add_flow(datapath, 1, match, actions)

		data = pkt_orig.data
		out = parser.OFPPacketOut(datapath=datapath, 
									buffer_id=ofproto.OFP_NO_BUFFER,
									in_port=porta_saida, 
									actions=actions,
									data=data)
		
		datapath.send_msg(out)"""

	def _send_packet(self, datapath, port, pkt):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		pkt.serialize()
		#self.logger.info("packet %s "%(pkt,))
		data = pkt.data
		actions = [parser.OFPActionOutput (port=port)]
		out = parser.OFPPacketOut(datapath=datapath, 
									buffer_id=ofproto.OFP_NO_BUFFER,
									in_port=ofproto.OFPP_CONTROLLER, 
									actions=actions,
									data=data)
		
		datapath.send_msg(out)

	def _send_packet_v2(self, datapath, port, pkt):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser		
		#self.logger.info("packet %s "%(pkt,))
		pkt.serialize()
		data = pkt.data
		actions = [parser.OFPActionOutput (port=port)]
		out = parser.OFPPacketOut(datapath=datapath, 
									buffer_id=ofproto.OFP_NO_BUFFER,
									in_port=port, 
									actions=actions,
									data=data)
		
		datapath.send_msg(out)
	
	def send_port_stats_request(self, datapath):
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
		datapath.send_msg(req)

	@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
	def port_stats_reply_handler(self, ev):
		datapath = ev.msg.datapath
		dpid = datapath.id
		ports = []
		for stat in ev.msg.body:
			ports.append(stat.port_no)
		ports = ports[1:]
		for port in ports:
			if(dpid==1):
				self.all_ports_s1.append(port)		
			elif(dpid==2):
				self.all_ports_s2.append(port)
			elif(dpid==3):
				self.all_ports_s3.append(port)
	
	def same_subnet(self, pkt_src_ip, pkt_dst_ip, netmask):
		bin_src_ip = self.dec_to_bin(pkt_src_ip)
		bin_dst_ip = self.dec_to_bin(pkt_dst_ip)
		bin_nm_ip = self.dec_to_bin(netmask)
		bw_src = int(bin_src_ip) & int(bin_nm_ip)
		bw_dst = int(bin_dst_ip) & int(bin_nm_ip)
		return bw_dst==bw_src


	def dec_to_bin(self,ip):
		ip_array = list(filter(None, ip.split('.')))
		if len(ip_array) != 4:
			raise NotValidIPException('Invalid IP Address format.')
		else:
			ip_bin = ['{0:08b}'.format(int(el)) for el in ip_array]
		return ''.join(ip_bin)