ONOS DOCKER

docker ps
docker ps -a
docker images
docker start onos

**# Voir les logs pour confirmer que ONOS est prêt**
**docker logs -f onos**
**http://localhost:8181/onos/ui**

Login : onos
Mot de passe : rocks



docker exec -it onos /root/onos/apache-karaf-4.2.9/bin/client

app activate org.onosproject.openflow

app activate org.onosproject.fwd

app activate org.onosproject.drivers



logout







VMware1 : pont de vmware 

Sur OVS-1, configure le contrôleur

bash# Donner une IP à OVS-1

ip addr add 192.168.30.20/24 dev eth0

ip link set eth0 up



\# Tester vers la VM

ping -c 3 192.168.30.130



\# Configurer ONOS comme contrôleur

ovs-vsctl set-controller br0 tcp:192.168.30.130:6653

ovs-vsctl set bridge br0 protocols=OpenFlow13





logs de ovs tail -f /var/log/openvswitch/ovs-vswitchd.log



\# Autoriser ICMP

netsh advfirewall firewall add rule name="ICMP VMnet1" protocol=icmpv4:8,any dir=in action=allow



\# Autoriser port 6653 OpenFlow

netsh advfirewall firewall add rule name="ONOS OpenFlow" protocol=TCP dir=in localport=6653 action=allow









ip link show

\# Donner l'IP directement sur br0 (l'interface interne OVS)

ip addr add 192.168.30.20/24 dev br0

ip link set br0 up



\# Tester

ping -c 3 192.168.30.130



donner une commende pr suprimer controlleir









Ouvre le terminal de OpenvSwitch-1 et tape ces commandes une par une :

Commande 1 : Voir les bridges existants

bashovs-vsctl show

Commande 2 : Voir le nom du bridge

bashovs-vsctl list-br









**Configuré routeur intervlan (gatway):**



enable

configure terminal



interface f0/0

 no shutdown



interface f0/0.10

 encapsulation dot1Q 10

 ip address 192.168.10.254 255.255.255.0

 no shutdown



interface f0/0.30

 encapsulation dot1Q 30

 ip address 192.168.30.254 255.255.255.0

 no shutdown



interface f0/0.40

 encapsulation dot1Q 40

 ip address 192.168.40.254 255.255.255.0

 no shutdown



end

write memory



**config mgmt vlan dans ovs :**



ovs-vsctl set+ port eth3 trunk=10,30,40 (relier avec un ovs)

ovs-vsctl set port eth5 tag=40 (relier avec une hoste dans vlan 40)

ovs-vsctl set bridge br0 stp\_enable=true (activer stp protocole dans les 3 switch)

ip addr add 192.168.10.1/24 dev mgmt

ip link set mgmt up



**Config nat dans le routeur pour acceder a internet:**



enable

configure terminal



! Interface vers NAT1 (Internet) - outside

interface f1/0

 ip address dhcp

 ip nat outside

 no shutdown



! Interfaces internes - inside

interface f0/0.10

 ip nat inside



interface f0/0.30

 ip nat inside



interface f0/0.40

 ip nat inside



! ACL - autoriser les reseaux internes

access-list 1 permit 192.168.10.0 0.0.0.255

access-list 1 permit 192.168.30.0 0.0.0.255

access-list 1 permit 192.168.40.0 0.0.0.255



! NAT PAT overload

ip nat inside source list 1 interface f1/0 overload



! Route par defaut vers Internet

ip route 0.0.0.0 0.0.0.0 192.168.122.1





end

write memory

















CONNECTER CONTROLLEUR ET OVS

VM :



\# Vérifier l'IP de la VM

ip addr show



\# Tester internet

ping 8.8.8.8



\# Résultat obtenu :

\# inet 192.168.30.130/24 ✅





\# Aller dans le dossier

cd \~/Desktop



\# Activer l'environnement Python

source ryu-env39/bin/activate



\# Lancer le contrôleur

ryu-manager controller\_stp.py



\# Vérifier que Ryu écoute

ss -tlnp | grep 6653

\# Résultat : LISTEN 0.0.0.0:6653 ✅





**ovs :**

 dans vm voir ip de controlleur :  **ip a**



ovs-vsctl set-controller br0 tcp:IP\_CONTROLLER:6633

ovs-vsctl set bridge br0 protocols=OpenFlow13



















**VM:**

\# Vérifier l'IP de la VM

ip addr show ens33



\# Vérifier que Ryu écoute

ss -tlnp | grep 6653



\# Lancer Ryu

cd \~/Desktop

source ryu-env39/bin/activate

ryu-manager --verbose ryu.app.simple\_switch\_13        #C'est le contrôleur officiel Ryu intégré !



\## 2️⃣ Configuration Cloud dans GNS3

Cloud1 → Configure →

VMware Network Adapter VMnet1 ✅



Cloud2 → Configure →

VMware Network Adapter VMnet1 ✅



Cloud3 → Configure →

VMware Network Adapter VMnet1 ✅







**config eth a chaque ovs reliee a cloud:**

**OVS1:**

\# Donner IP à ethX

ip addr add 192.168.30.100/24 dev ethX

ip link set eth15 up



\# Connecter à Ryu



**ovs-vsctl set-controller br0 tcp:192.168.30.130:6653      	(ip de vm 192.168.30.130)**

**ovs-vsctl set bridge br0 protocols=OpenFlow13**

**ovs-vsctl show | grep -A3 Controller**



\# Désactiver STP

ovs-vsctl set bridge br0 stp\_enable=false

ovs-vsctl set bridge br0 rstp\_enable=false



\# Vérifier

ping -c 3 192.168.30.130

ovs-vsctl show | grep -A2 Controller











\# Connexion Ryu ok ?

**ovs-vsctl show | grep -A2 Controller**

\# → is\_connected: true ✅



\# Flows installés ?

ovs-ofctl dump-flows br0



\# STP désactivé ?

ovs-vsctl get bridge br0 stp\_enable

\# → false ✅

```



\\\\### Dans VM Ubuntu (logs Ryu) :

```

connected to 0000caadd0a2f54a ← OVS-1 ✅

connected to 0000....          ← OVS-2 ✅

connected to 0000....          ← OVS-3 ✅

```



---

\\\*\\\*RESET DE GNS3:\\\*\\\* 

\\\\## 6️⃣ Edit config GNS3 (sauvegarde permanente)

```

auto eth15

iface eth15 inet static

    address 192.168.30.100    ← (101 OVS-2, 102 OVS-3)

    netmask 255.255.255.0

    up ovs-vsctl set-controller br0 tcp:192.168.30.130:6653

```











3\\\\. Test rapide - Lance ce contrôleur minimal :

Arrête Ryu et tape :

bashryu-manager --verbose ryu.app.simple\\\\\\\_switch\\\\\\\_13

C'est le contrôleur officiel Ryu intégré !





\\\\#Vérifie R1 dans GNS3 :

enable

show ip interface brief

show ip route





ping -c 3 192.168.30.130

ovs-vsctl show | grep -A2 Controller





source \\\~/Desktop/ryu-env39/bin/activate

\\\*\\\*ryu-manager x.py\\\*\\\*



controlleur pr intervlan

\\\*\\\*ryu-manager ryu.app.rest\\\\\\\_router ryu.app.ofctl\\\\\\\_rest\\\*\\\*









\\\*\\\*https://github.com/shubhscoder/RYU-SDN-Controller\\\*\\\*



\\\*\\\*2controleur\\\*\\\*

\\\*\\\*ryu-manager topo\\\\\\\_discovery.py intervlan\\\\\\\_router.py --observe-links\\\*\\\*



