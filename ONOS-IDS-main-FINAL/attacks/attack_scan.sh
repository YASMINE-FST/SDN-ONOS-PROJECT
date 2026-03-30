#!/bin/bash
# Port Scan — reconnaissance avant exploitation
echo "[ATTACK] Port Scan : 192.168.1.10 → 192.168.1.20"
nmap -sS \
  --min-rate 1000 \
  -p 1-1024 \
  192.168.1.20
