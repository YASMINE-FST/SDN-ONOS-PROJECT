#!/usr/bin/env python3
"""
================================================================================
Topologie SDN avec DHCP Option 43 pour ONOS
================================================================================
Auteur: Projet PFE
Description: Topologie avec 5 switches et 8 hosts
             - Serveur DHCP intégré avec Option 43 vers ONOS
             - Découverte automatique des switches par ONOS
             - Tous les hosts reçoivent leurs IP via DHCP
================================================================================

Schéma de la topologie:

                          ┌─────────────────────────────────────┐
                          │         CONTROLEUR ONOS             │
                          │        172.18.0.1:6653              │
                          └─────────────────────────────────────┘
                                            ▲
                                            │ OpenFlow
                                            │
    ┌─────────────────────────────────────────────────────────────────────────┐
    │                           RÉSEAU MININET                                │
    │                                                                         │
    │                              ┌─────┐                                    │
    │                    ┌─────────│ s1  │─────────┐                          │
    │                    │         └─────┘         │                          │
    │                    │           │             │                          │
    │                    │           │             │                          │
    │              ┌─────┴─────┐     │     ┌───────┴─────┐                    │
    │              │           │     │     │             │                    │
    │           ┌─▼─┐       ┌─▼─┐   │   ┌─▼─┐         ┌─▼─┐                  │
    │           │s2 │       │s3 │───┼───│s4 │         │s5 │                   │
    │           └─┬─┘       └─┬─┘   │   └─┬─┘         └─┬─┘                   │
    │             │           │     │     │             │                     │
    │    ┌────────┼───────────┼─────┼─────┼─────────────┼────────┐            │
    │    │        │           │     │     │             │        │            │ 
    │    ▼           ▼                ▼       ▼       ▼                   ▼          ▼            │ 
    │ ┌────┐  ┌────┐      ┌────┐ ┌────┐ ┌────┐      ┌────┐  ┌────┐            │
    │ │ h1 │  │ h2 │      │ h3 │ │ h4 │ │ h5 │      │ h6 │  │ h7 │            │
    │ └────┘  └────┘      └────┘ └────┘ └────┘      └────┘  └────┘            │
    │                                                                         │
    │                              ┌─────┐                                    │
    │                              │  d  │  ← Serveur DHCP (10.0.0.254)      │
    │                              └─────┘    Option 43: tcp:172.18.0.1:6653  │
    └─────────────────────────────────────────────────────────────────────────┘

Légende:
    s1-s5 : Switches OpenFlow (OVS)
    h1-h7 : Hosts clients DHCP (reçoivent IP automatiquement)
    d     : Serveur DHCP (IP statique 10.0.0.254)
    ONOS  : Contrôleur SDN (172.18.0.1:6653)

Fonctionnalités:
    ✅ Découverte automatique des switches par ONOS
    ✅ Distribution automatique des IP via DHCP (Option 43)
    ✅ Topologie maillée pour tester STP et routage
    ✅ Compatible avec ONOS (OpenFlow 1.3)
================================================================================
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import time


class OVSSwitch13(OVSSwitch):
    """OVS Switch forcé en OpenFlow 1.3 (compatible ONOS)"""
    def __init__(self, name, **params):
        OVSSwitch.__init__(self, name, protocols='OpenFlow13', **params)


class TopoWithDHCP(Topo):
    """
    Topologie avec 5 switches et 8 hosts (7 clients + 1 serveur DHCP)
    Structure maillée pour tester la robustesse du réseau
    """
    
    def build(self, bandwidth=100, delay='2ms'):
        """
        Construction de la topologie
        
        Paramètres:
            bandwidth: Bande passante par défaut (Mbps)
            delay: Délai par défaut (ms)
        """
        link_opts = dict(bw=bandwidth, delay=delay, use_htb=True)
        
        # =============================================================
        # 1. Création des switches (5 switches)
        # =============================================================
        switches = []
        for i in range(1, 6):
            s = self.addSwitch(f's{i}')
            switches.append(s)
        
        # =============================================================
        # 2. Création des hosts (7 clients DHCP + 1 serveur DHCP)
        # =============================================================
        
        # Serveur DHCP (IP statique sera configurée plus tard)
        dhcp_server = self.addHost('d', ip=None)
        
        # Clients DHCP (IP automatique via DHCP)
        clients = []
        for i in range(1, 8):
            client = self.addHost(f'h{i}', ip=None)
            clients.append(client)
        
        # =============================================================
        # 3. Connexions entre switches (topologie maillée)
        # =============================================================
        # Structure: s1 central, s2,s3,s4,s5 en étoile + liens entre eux
        # s1 connecté à tous
        for i in range(2, 6):
            self.addLink(switches[0], switches[i-1], **link_opts)  # s1-s2, s1-s3, s1-s4, s1-s5
        
        # Liens supplémentaires entre switches (maille)
        self.addLink(switches[1], switches[2], **link_opts)  # s2-s3
        self.addLink(switches[2], switches[3], **link_opts)  # s3-s4
        self.addLink(switches[3], switches[4], **link_opts)  # s4-s5
        self.addLink(switches[4], switches[1], **link_opts)  # s5-s2
        self.addLink(switches[1], switches[3], **link_opts)  # s2-s4
        self.addLink(switches[2], switches[4], **link_opts)  # s3-s5
        
        # =============================================================
        # 4. Connexions des hosts aux switches
        # =============================================================
        
        # Serveur DHCP sur s1
        self.addLink(dhcp_server, switches[0], **link_opts)
        
        # Clients répartis sur les switches
        # h1,h2 sur s2 | h3,h4 sur s3 | h5,h6 sur s4 | h7 sur s5
        self.addLink(clients[0], switches[1], **link_opts)   # h1 -> s2
        self.addLink(clients[1], switches[1], **link_opts)   # h2 -> s2
        self.addLink(clients[2], switches[2], **link_opts)   # h3 -> s3
        self.addLink(clients[3], switches[2], **link_opts)   # h4 -> s3
        self.addLink(clients[4], switches[3], **link_opts)   # h5 -> s4
        self.addLink(clients[5], switches[3], **link_opts)   # h6 -> s4
        self.addLink(clients[6], switches[4], **link_opts)   # h7 -> s5


def setup_dhcp_server(host):
    """
    Configure et démarre le serveur DHCP sur le host 'd'
    L'Option 43 contient l'adresse du contrôleur ONOS
    """
    info("\n" + "─"*50 + "\n")
    info("📡 CONFIGURATION DU SERVEUR DHCP\n")
    info("─"*50 + "\n")
    
    # Nettoyer l'interface
    host.cmd('ip addr flush dev d-eth0 2>/dev/null')
    
    # Donner une IP statique au serveur DHCP
    host.cmd('ip addr add 10.0.0.254/24 dev d-eth0')
    host.cmd('ip link set d-eth0 up')
    info("   ✅ Serveur DHCP: IP statique 10.0.0.254\n")
    
    # Adresse du contrôleur ONOS (à ajuster selon ton environnement)
    ONOS_IP = '172.18.0.1'
    ONOS_PORT = 6653
    onos_str = f"tcp:{ONOS_IP}:{ONOS_PORT}"
    
    # Configuration dnsmasq avec Option 43
    config = f"""interface=d-eth0
bind-interfaces
dhcp-range=10.0.0.100,10.0.0.200,255.255.255.0,600s
dhcp-option=3,10.0.0.254
dhcp-option=6,8.8.8.8
dhcp-option=43,{onos_str}
log-queries
"""
    
    host.cmd('cat > /tmp/dnsmasq.conf << "EOF"\n' + config + '\nEOF')
    host.cmd('pkill dnsmasq 2>/dev/null')
    host.cmd('dnsmasq -C /tmp/dnsmasq.conf --no-daemon &')
    
    info(f"   ✅ Serveur DHCP démarré\n")
    info(f"   📡 Option 43: {onos_str}\n")
    info("\n")
    
    time.sleep(2)


def setup_dhcp_clients(hosts):
    """
    Démarre les clients DHCP sur tous les hosts (sauf le serveur)
    """
    info("─"*50 + "\n")
    info("📡 DÉMARRAGE DES CLIENTS DHCP\n")
    info("─"*50 + "\n")
    
    for host in hosts:
        # Nettoyer l'interface
        host.cmd(f'ip addr flush dev {host.name}-eth0 2>/dev/null')
        # Démarrer dhclient en arrière-plan
        host.cmd(f'dhclient -v {host.name}-eth0 &')
        info(f"   {host.name} demande une IP...\n")
    
    info("\n")
    time.sleep(8)  # Attendre que toutes les IPs soient attribuées


def configure_switches(net, controller_ip='172.18.0.1', controller_port=6653):
    """
    Configure tous les switches pour se connecter à ONOS
    """
    info("─"*50 + "\n")
    info("🔧 CONFIGURATION DES SWITCHES POUR ONOS\n")
    info("─"*50 + "\n")
    
    for switch in net.switches:
        switch.cmd(f'ovs-vsctl set-controller {switch.name} tcp:{controller_ip}:{controller_port}')
        info(f"   {switch.name} → tcp:{controller_ip}:{controller_port}\n")
    
    time.sleep(5)
    
    # Vérifier les connexions
    info("\n🔍 VÉRIFICATION DES CONNEXIONS:\n")
    connected = 0
    for switch in net.switches:
        result = switch.cmd('ovs-vsctl show')
        if "is_connected: true" in result:
            info(f"   ✅ {switch.name} CONNECTÉ à ONOS\n")
            connected += 1
        else:
            info(f"   ❌ {switch.name} NON CONNECTÉ\n")
    
    info(f"\n   Total: {connected}/{len(net.switches)} switches connectés\n")
    info("\n")


def show_ips(hosts):
    """
    Affiche les IPs obtenues par tous les hosts
    """
    info("─"*50 + "\n")
    info("📋 IPS OBTENUES PAR DHCP\n")
    info("─"*50 + "\n")
    
    for host in hosts:
        ip = host.cmd(f'ip addr show {host.name}-eth0 | grep "inet " | awk \'{{print $2}}\'').strip()
        if ip:
            info(f"   ✅ {host.name}: {ip}\n")
        else:
            info(f"   ❌ {host.name}: pas d'IP (erreur DHCP)\n")
    
    info("\n")


def show_switch_status(net):
    """
    Affiche le statut détaillé des switches
    """
    info("─"*50 + "\n")
    info("🔌 STATUT DES SWITCHES\n")
    info("─"*50 + "\n")
    
    for switch in net.switches:
        info(f"\n   {switch.name}:\n")
        result = switch.cmd('ovs-vsctl show')
        # Extraire les infos importantes
        lines = result.split('\n')
        for line in lines:
            if 'Controller' in line or 'is_connected' in line or 'fail_mode' in line:
                info(f"      {line.strip()}\n")


def run_topology():
    """
    Fonction principale : lance la topologie complète
    """
    info("\n")
    info("╔" + "="*58 + "╗\n")
    info("║" + " "*15 + "TOPOLOGIE SDN AVEC DHCP OPTION 43" + " "*15 + "║\n")
    info("╚" + "="*58 + "╝\n")
    info("\n")
    info("📋 INFORMATIONS:\n")
    info("   • 5 switches (OpenFlow 1.3)\n")
    info("   • 8 hosts (1 serveur DHCP + 7 clients)\n")
    info("   • Topologie maillée avec STP\n")
    info("   • Serveur DHCP avec Option 43\n")
    info("   • Contrôleur ONOS: 172.18.0.1:6653\n")
    info("\n")
    
    # Créer la topologie
    topo = TopoWithDHCP()
    
    # Créer le réseau Mininet
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='172.18.0.1', port=6653),
        switch=OVSSwitch13,
        link=TCLink,
        autoSetMacs=True,
        waitConnected=True
    )
    
    # Démarrer le réseau
    net.start()
    info("\n✅ RÉSEAU DÉMARRÉ\n")
    
    # Récupérer les éléments
    dhcp_server = net.get('d')
    clients = [net.get(f'h{i}') for i in range(1, 8)]
    
    # 1. Configurer le serveur DHCP
    setup_dhcp_server(dhcp_server)
    
    # 2. Démarrer les clients DHCP
    setup_dhcp_clients(clients)
    
    # 3. Afficher les IPs obtenues
    show_ips(clients)
    
    # 4. Configurer les switches pour ONOS
    configure_switches(net, controller_ip='172.18.0.1', controller_port=6653)
    
    # 5. Afficher le statut des switches
    show_switch_status(net)
    
    # 6. Informations finales
    info("\n")
    info("╔" + "="*58 + "╗\n")
    info("║" + " "*20 + "MININET CLI" + " "*20 + "║\n")
    info("╚" + "="*58 + "╝\n")
    info("\n")
    info("📋 COMMANDES UTILES:\n")
    info("   mininet> pingall                    # Tester la connectivité\n")
    info("   mininet> h1 ping h7 -c 3            # Ping entre deux clients\n")
    info("   mininet> h1 ifconfig                # Voir IP de h1\n")
    info("   mininet> d ifconfig                 # Voir IP du serveur DHCP\n")
    info("   mininet> sh ovs-vsctl show          # Voir les connexions switches\n")
    info("   mininet> iperf h1 h2                # Test de bande passante\n")
    info("   mininet> exit                       # Quitter\n")
    info("\n")
    info("⚠️  Pour voir les switches dans ONOS, exécute dans un autre terminal:\n")
    info("   docker exec -it onos2 bin/onos-cli\n")
    info("   onos> devices\n")
    info("   onos> hosts\n")
    info("   onos> links\n")
    info("\n")
    info("═"*60 + "\n")
    
    # Ouvrir la CLI Mininet
    CLI(net)
    
    # Nettoyage
    info("\n🧹 Nettoyage en cours...\n")
    dhcp_server.cmd('pkill dnsmasq')
    net.stop()
    info("\n✅ TEST TERMINÉ\n")


if __name__ == '__main__':
    setLogLevel('info')
    run_topology()
