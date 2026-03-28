#!/usr/bin/env python3
"""
Extraction des features d'un pcap en streaming avec tshark
Utilise beaucoup moins de mémoire
"""

import subprocess
import pandas as pd
import numpy as np
from collections import defaultdict
import sys
import os

COLUMNS = [
    "flow_duration", "protocol",
    "fwd_pkt_count", "bwd_pkt_count",
    "fwd_bytes_total", "bwd_bytes_total",
    "fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_max", "fwd_pkt_len_min",
    "bwd_pkt_len_mean", "bwd_pkt_len_std", "bwd_pkt_len_max", "bwd_pkt_len_min",
    "flow_bytes_per_sec", "flow_pkts_per_sec",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags",
    "fwd_urg_flags", "bwd_urg_flags",
    "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count", "urg_flag_count",
    "cwe_flag_count", "ece_flag_count",
    "fwd_header_len", "bwd_header_len",
    "fwd_pkts_per_sec", "bwd_pkts_per_sec",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    "down_up_ratio", "avg_pkt_size", "avg_fwd_segment_size", "avg_bwd_segment_size",
    "fwd_header_len2",
    "subflow_fwd_pkts", "subflow_fwd_bytes", "subflow_bwd_pkts", "subflow_bwd_bytes",
    "init_fwd_win_bytes", "init_bwd_win_bytes",
    "fwd_act_data_pkts", "fwd_seg_size_min",
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
    "unique_src_mac", "unique_dst_mac", "arp_reply_ratio", "bcast_ratio",
    "dhcp_offer_count", "stp_bpdu_count",
    "http_payload_len", "http_entropy", "has_sql_keyword", "has_script_tag",
    "ssl_version_num", "session_reuse_ratio"
]

def extract_flows_tshark(pcap_file, max_flows=3000):
    """
    Extrait les flux avec tshark (streaming, mémoire faible)
    """
    print(f"📁 Analyse du pcap: {pcap_file}")
    
    # Commande tshark pour extraire les stats de flux
    cmd = [
        "tshark", "-r", pcap_file,
        "-T", "fields",
        "-e", "frame.time_relative",
        "-e", "ip.proto",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "frame.len",
        "-e", "tcp.flags",
        "-e", "eth.src", "-e", "eth.dst",
        "-E", "separator=|"
    ]
    
    print("🔍 Extraction des paquets (streaming)...")
    
    flows = defaultdict(list)
    count = 0
    
    # Exécuter tshark et lire la sortie ligne par ligne
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
    
    for line in proc.stdout:
        count += 1
        if count % 500000 == 0:
            print(f"   {count:,} paquets traités...")
        
        parts = line.strip().split('|')
        if len(parts) < 11:
            continue
        
        try:
            time_sec = float(parts[0]) if parts[0] else 0
            proto = int(parts[1]) if parts[1] else 0
            src_ip = parts[2]
            dst_ip = parts[3]
            
            # Ports selon protocole
            if proto == 6:  # TCP
                sport = int(parts[4]) if parts[4] else 0
                dport = int(parts[5]) if parts[5] else 0
                flags = int(parts[9]) if len(parts) > 9 and parts[9] else 0
            elif proto == 17:  # UDP
                sport = int(parts[6]) if parts[6] else 0
                dport = int(parts[7]) if parts[7] else 0
                flags = 0
            else:
                sport = 0
                dport = 0
                flags = 0
            
            pkt_len = int(parts[8]) if parts[8] else 0
            src_mac = parts[10] if len(parts) > 10 else None
            dst_mac = parts[11] if len(parts) > 11 else None
            
            # Clé de flux
            flow_key = (src_ip, dst_ip, proto, sport, dport)
            
            flows[flow_key].append({
                'time': time_sec,
                'len': pkt_len,
                'flags': flags,
                'src_mac': src_mac,
                'dst_mac': dst_mac
            })
            
        except (ValueError, IndexError):
            continue
    
    proc.terminate()
    print(f"   Total paquets traités: {count:,}")
    print(f"   Flux identifiés: {len(flows)}")
    
    # Limiter le nombre de flux
    if len(flows) > max_flows:
        print(f"   Limitation à {max_flows} flux")
        flow_items = list(flows.items())[:max_flows]
    else:
        flow_items = list(flows.items())
    
    # Extraire les features
    features_list = []
    print("📊 Extraction des features...")
    
    for i, (flow_key, pkts) in enumerate(flow_items):
        if i % 500 == 0:
            print(f"   Traitement flux: {i}/{len(flow_items)}")
        
        if len(pkts) < 2:
            continue
        
        times = [p['time'] for p in pkts]
        lens = [p['len'] for p in pkts]
        flags = [p['flags'] for p in pkts]
        
        duration = max(times) - min(times)
        packet_count = len(pkts)
        byte_count = sum(lens)
        protocol = flow_key[2]
        
        mean_pkt_len = byte_count / packet_count if packet_count > 0 else 0
        flow_sec = duration + 1e-9
        pkt_per_sec = packet_count / flow_sec
        byte_per_sec = byte_count / flow_sec
        
        # IAT
        if len(times) > 1:
            iats = [times[i+1] - times[i] for i in range(len(times)-1)]
            iats_us = [iat * 1_000_000 for iat in iats]
            avg_iat = np.mean(iats_us) if iats_us else 0
            std_iat = np.std(iats_us) if iats_us else 0
            max_iat = max(iats_us) if iats_us else 0
            min_iat = min(iats_us) if iats_us else 0
        else:
            avg_iat = std_iat = max_iat = min_iat = 0
        
        # Flags TCP
        syn_count = sum(1 for f in flags if f & 0x02)
        ack_count = sum(1 for f in flags if f & 0x10)
        fin_count = sum(1 for f in flags if f & 0x01)
        rst_count = sum(1 for f in flags if f & 0x04)
        psh_count = sum(1 for f in flags if f & 0x08)
        
        # Vecteur
        f = [0.0] * 82
        
        f[0] = duration * 1_000_000
        f[1] = protocol
        f[2] = packet_count
        f[3] = 0
        f[4] = byte_count
        f[5] = 0
        f[6] = mean_pkt_len
        f[7] = np.std(lens) if lens else 0
        f[8] = max(lens) if lens else 0
        f[9] = min(lens) if lens else 0
        f[14] = byte_per_sec
        f[15] = pkt_per_sec
        
        f[16] = avg_iat
        f[17] = std_iat
        f[18] = max_iat
        f[19] = min_iat
        f[20] = avg_iat
        f[21] = std_iat
        f[22] = max_iat
        f[23] = min_iat
        
        f[32] = fin_count
        f[33] = syn_count
        f[34] = rst_count
        f[35] = psh_count
        f[36] = ack_count
        
        f[40] = packet_count * 20
        f[41] = 0
        
        f[44] = min(lens) if lens else 0
        f[45] = max(lens) if lens else 0
        f[46] = mean_pkt_len
        f[47] = np.std(lens) if lens else 0
        f[48] = (np.std(lens) ** 2) if lens else 0
        
        f[54] = packet_count
        f[55] = byte_count
        
        macs = set([p['src_mac'] for p in pkts if p['src_mac']])
        f[70] = len(macs) if macs else 1
        f[71] = 1
        
        features_list.append(f)
    
    return np.array(features_list)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract_features_tshark.py <pcap_file> [output_file] [max_flows]")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "dataset/real_features.csv"
    max_flows = int(sys.argv[3]) if len(sys.argv) > 3 else 3000
    
    if not os.path.exists(pcap_file):
        print(f"❌ Fichier introuvable: {pcap_file}")
        sys.exit(1)
    
    print("\n" + "="*50)
    print("EXTRACTION DES FEATURES (STREAMING)")
    print("="*50)
    
    features = extract_flows_tshark(pcap_file, max_flows)
    
    df = pd.DataFrame(features, columns=COLUMNS)
    df.to_csv(output_file, index=False)
    
    print(f"\n✅ Features sauvegardées: {output_file}")
    print(f"   {len(df)} flux, {len(COLUMNS)} features")
    print(f"\n📊 STATISTIQUES:")
    print(f"   Durée moyenne: {df['flow_duration'].mean():.0f} µs")
    print(f"   Paquets moyen: {df['fwd_pkt_count'].mean():.0f}")
    print(f"   Bytes moyen: {df['fwd_bytes_total'].mean():.0f}")

if __name__ == "__main__":
    main()
