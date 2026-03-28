#!/usr/bin/env python3
"""
Topologie avec boucle (STP) + Serveur DHCP avec Option 43
Version avec noms simples (comme ta topologie qui marche)
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time

class OVSSwitch13(OVSSwitch):
    """OVS Switch forcé en OpenFlow 1.3"""
    def __init__(self, name, **params):
        OVSSwitch.__init__(self, name, protocols='OpenFlow13', **params)


class TopoWithDHCP(Topo):
    """
    Topologie triangle (s1-s2-s3) avec :
    - Serveur DHCP (d) sur s1
    - Clients DHCP (h1, h2, h3) sur s2, s3, s1
    """
    def build(self, bandwidth=100, delay='2ms'):
        link_opts = dict(bw=bandwidth, delay=delay, use_htb=True)
        
        # Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        
        # Serveur DHCP (nom simple: d)
        d = self.addHost('d', ip=None)  # IP configurée plus tard
        
        # Clients DHCP (noms simples comme dans ta topo)
        h1 = self.addHost('h1', ip=None)
        h2 = self.addHost('h2', ip=None)
        h3 = self.addHost('h3', ip=None)
        
        # Connexions switches (comme dans ta topologie)
        self.addLink(s1, s2, **link_opts)
        self.addLink(s2, s3, **link_opts)
        self.addLink(s3, s1, **link_opts)
        
        # Connexions hosts
        self.addLink(d, s1, **link_opts)   # Serveur DHCP sur s1
        self.addLink(h1, s2, **link_opts)  # Client sur s2
        self.addLink(h2, s3, **link_opts)  # Client sur s3
        self.addLink(h3, s1, **link_opts)  # Client sur s1


def setup_dhcp_server(host):
    """Configure et démarre le serveur DHCP sur le host"""
    info("\n📡 Configuration du serveur DHCP...\n")
    
    # Donner une IP statique au serveur
    host.cmd('ip addr add 10.0.0.254/24 dev d-eth0')
    host.cmd('ip link set d-eth0 up')
    info("   ✅ Serveur DHCP: 10.0.0.254\n")
    
    # Configurer dnsmasq avec Option 43
    onos_str = "tcp:172.18.0.1:6653"
    
    config = f"""interface=d-eth0
bind-interfaces
dhcp-range=10.0.0.100,10.0.0.200,255.255.255.0,600s
dhcp-option=3,10.0.0.254
dhcp-option=6,8.8.8.8
dhcp-option=43,{onos_str}
"""
    
    host.cmd('cat > /tmp/dnsmasq.conf << "EOF"\n' + config + '\nEOF')
    host.cmd('pkill dnsmasq 2>/dev/null')
    host.cmd('dnsmasq -C /tmp/dnsmasq.conf --no-daemon &')
    info(f"   ✅ Serveur DHCP démarré\n")
    info(f"   📡 Option 43: {onos_str}\n")
    
    time.sleep(2)


def setup_dhcp_clients(hosts):
    """Démarre les clients DHCP"""
    info("\n📡 Démarrage des clients DHCP...\n")
    
    for host in hosts:
        host.cmd(f'ip addr flush dev {host.name}-eth0 2>/dev/null')
        host.cmd('dhclient -v &')
        info(f"   {host.name} demande une IP...\n")
    
    time.sleep(5)


def configure_switches(net, controller_ip='172.18.0.1', controller_port=6653):
    """Configure les switches pour se connecter à ONOS"""
    info("\n🔧 Configuration des switches pour ONOS...\n")
    
    for switch in net.switches:
        switch.cmd(f'ovs-vsctl set-controller {switch.name} tcp:{controller_ip}:{controller_port}')
        info(f"   {switch.name} → tcp:{controller_ip}:{controller_port}\n")
    
    time.sleep(3)
    
    # Vérifier les connexions
    info("\n🔍 Vérification des connexions:\n")
    for switch in net.switches:
        result = switch.cmd('ovs-vsctl show')
        if "is_connected: true" in result:
            info(f"   ✅ {switch.name} CONNECTÉ à ONOS\n")
        else:
            info(f"   ❌ {switch.name} NON CONNECTÉ\n")


def show_ips(hosts):
    """Affiche les IPs des hosts"""
    info("\n📋 IPs obtenues:\n")
    
    for host in hosts:
        ip = host.cmd(f'ip addr show {host.name}-eth0 | grep "inet " | awk \'{{print $2}}\'').strip()
        if ip:
            info(f"   ✅ {host.name}: {ip}\n")
        else:
            info(f"   ❌ {host.name}: pas d'IP\n")


def run_topology():
    info("\n" + "="*60 + "\n")
    info("🧪 TOPOLOGIE AVEC BOUCLE + DHCP OPTION 43\n")
    info("   - Serveur DHCP (d) sur s1\n")
    info("   - Clients DHCP (h1, h2, h3)\n")
    info("   - Option 43: tcp:172.18.0.1:6653\n")
    info("="*60 + "\n")
    
    # Créer la topologie
    topo = TopoWithDHCP()
    
    # Créer le réseau
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='172.18.0.1', port=6653),
        switch=OVSSwitch13,
        link=TCLink,
        autoSetMacs=True,
        waitConnected=True
    )
    
    net.start()
    info("\n✅ Réseau démarré\n")
    
    # Récupérer les éléments
    d = net.get('d')      # Serveur DHCP
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    
    # Configurer le serveur DHCP
    setup_dhcp_server(d)
    
    # Configurer les clients DHCP
    setup_dhcp_clients([h1, h2, h3])
    
    # Afficher les IPs
    show_ips([h1, h2, h3])
    
    # Configurer les switches pour ONOS
    configure_switches(net, controller_ip='172.18.0.1', controller_port=6653)
    
    info("\n" + "="*60 + "\n")
    info("🖥️  MININET CLI\n")
    info("Commandes à tester:\n")
    info("   mininet> pingall\n")
    info("   mininet> h1 ifconfig\n")
    info("   mininet> h2 ifconfig\n")
    info("   mininet> h3 ifconfig\n")
    info("   mininet> d ifconfig\n")
    info("   mininet> sh ovs-vsctl show\n")
    info("="*60 + "\n")
    
    CLI(net)
    
    # Nettoyage
    d.cmd('pkill dnsmasq')
    net.stop()
    info("\n✅ Test terminé\n")


if __name__ == '__main__':
    setLogLevel('info')
    run_topology()
