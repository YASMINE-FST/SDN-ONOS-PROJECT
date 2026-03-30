#!/usr/bin/env python3
"""
Topologie IDS realiste pour tests SOC
  h1 = Attaquant  (192.168.1.10 / MAC realiste)
  h2 = Victime    (192.168.1.20 / MAC realiste)
  h3 = Client     (192.168.1.30 / MAC realiste)
  s1, s2, s3 = OVS switches connectes a ONOS
"""
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.link import TCLink

def run():
    setLogLevel('info')
    net = Mininet(switch=OVSSwitch, link=TCLink)

    # Controller ONOS
    onos = net.addController('onos',
                             controller=RemoteController,
                             ip='127.0.0.1',
                             port=6653)

    # Switches
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    s3 = net.addSwitch('s3', protocols='OpenFlow13')

    # Hotes avec MACs et IPs realistes
    h1 = net.addHost('h1',
                     mac='a4:c3:f0:85:12:3e',
                     ip='192.168.1.10/24')   # Attaquant

    h2 = net.addHost('h2',
                     mac='b8:27:eb:4f:a1:92',
                     ip='192.168.1.20/24')   # Victime (serveur web)

    h3 = net.addHost('h3',
                     mac='dc:a6:32:11:87:5c',
                     ip='192.168.1.30/24')   # Client legitime

    # Liens avec bande passante et delai realistes
    net.addLink(h1, s1, bw=100, delay='2ms')   # Attaquant → s1
    net.addLink(h2, s3, bw=100, delay='2ms')   # Victime → s3
    net.addLink(h3, s3, bw=100, delay='2ms')   # Client → s3
    net.addLink(s1, s2, bw=1000, delay='1ms')  # Backbone
    net.addLink(s2, s3, bw=1000, delay='1ms')  # Backbone

    net.start()

    # Configure la gateway sur chaque hote
    h1.cmd('ip route add default via 192.168.1.1')
    h2.cmd('ip route add default via 192.168.1.1')
    h3.cmd('ip route add default via 192.168.1.1')

    # Installe les outils d'attaque sur h1
    print("\n=== Topologie IDS SOC ===")
    print("h1 (Attaquant) : 192.168.1.10  MAC: a4:c3:f0:85:12:3e")
    print("h2 (Victime)   : 192.168.1.20  MAC: b8:27:eb:4f:a1:92")
    print("h3 (Client)    : 192.168.1.30  MAC: dc:a6:32:11:87:5c")
    print("Switches       : s1 -- s2 -- s3")
    print("Controller     : ONOS 127.0.0.1:6653")
    print("========================\n")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    run()
