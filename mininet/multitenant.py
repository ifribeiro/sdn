#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='127.0.0.1',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)

    info( '*** Add hosts\n')
    h1s2 = net.addHost('h1s2', cls=Host, ip='192.168.30.10/24', defaultRoute='h1s2-eth0')
    h1s1 = net.addHost('h1s1', cls=Host, ip='172.16.10.10/24', defaultRoute='h1s1-eth0')

    info( '*** Add links\n')
    net.addLink(s1, h1s2)
    net.addLink(h1s1, s1)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s1').start([c0])

    info( '*** Post configure switches and hosts\n')
    s1.cmd('ifconfig s1 172.16.10.1/24')
    h1s2.cmd('vconfig add h1s2-eth0 110')
    h1s2.cmd('ifconfig h1s2-eth0.110 172.16.10.1/24')
    h1s1.cmd('vconfig add h1s1-eth0 2')
    h1s1.cmd('ifconfig h1s1-eth0.2 172.16.10.1/24')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

