=== CAPTURE TCPDUMP - 12 ATTAQUES COMPLÈTES ===

📅 Date: 27 Mars 2026 - 00:06:28
📁 Session: session_12attaques_20260327_000628
📄 Fichier: all_attacks.pcap

📊 STATISTIQUES:
- Paquets capturés: 94,343,805
- Paquets reçus: 102,719,145
- Paquets perdus: 8,313,799
- Taille: ~10-12 Go

⚔️ ATTAQUES EFFECTUÉES (12/12):
1. ARP Spoofing (2 min) - ✅ FAIT
2. STP Spoofing (1 min) - ✅ FAIT
3. MAC Flooding (1 min) - ✅ FAIT
4. DHCP Spoofing (1 min) - ✅ FAIT
5. IP Spoofing (1 min) - ✅ FAIT
6. DDoS (2 min) - ✅ FAIT (h1 + h3)
7. Routing Protocol Attacks (1 min) - ✅ FAIT
8. SYN Flood (2 min) - ✅ FAIT
9. Port Scan (1 min) - ✅ FAIT
10. SQL Injection (1 min) - ✅ FAIT
11. SSL/TLS Stripping (1 min) - ✅ FAIT
12. Session Hijacking (1 min) - ✅ FAIT

🏗️ TOPOLOGIE:
- Type: Triangle avec boucle (s1-s2-s3-s1)
- h1: 10.0.0.1 (attaquant DDoS)
- h2: 10.0.0.2 (cible)
- h3: 10.0.0.3 (attaquant principal)

🛠️ OUTILS UTILISÉS:
- arpspoof (ARP Spoofing)
- Scapy (STP, MAC, DHCP, Routing, SSL Strip, Session Hijack)
- hping3 (IP Spoofing, DDoS, SYN Flood)
- nmap (Port Scan)
- Python requests (SQL Injection)

📝 NOTE:
Cette capture contient TOUTES les 12 attaques simulées dans l'ordre.
Utilisable pour réentraîner le modèle IA avec des données réelles.
