#!/usr/bin/env python3
"""
Extraction des 82 features d'un fichier pcap
Format compatible avec le dataset synthétique (CICFlowMeter-like)
"""

import numpy as np
import pandas as pd
from scapy.all import *
from collections import defaultdict
import os
import sys
import warnings
from tqdm import tqdm
warnings.filterwarnings("ignore")

# 82 colonnes (identique au dataset synthétique)
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

def extract_flow_features(pcap_file, sample_rate=0.1, max_flows=5000):
    """
    Extrait les features d'un fichier pcap

    Args:
        pcap_file: chemin du fichier pcap
        sample_rate: taux d'échantillonnage (0.1 = 10%)
        max_flows: nombre maximum de flux à extraire
    """
    print(f"📁 Lecture: {pcap_file}")

    # Lire les paquets
    packets = rdpcap(pcap_file)
    total = len(packets)
    print(f"   Total paquets: {total:,}")

    # Échantillonnage
    if sample_rate < 1.0:
        n_samples = int(total * sample_rate)
        indices = np.random.choice(total, n_samples, replace=False)
        packets = [packets[i] for i in sorted(indices)]
        print(f"   Échantillonnage: {len(packets):,} paquets ({sample_rate*100:.0f}%)")

    # Grouper par flux (5-tuple: src_ip, dst_ip, proto, src_port, dst_port)
    flows = defaultdict(list)

    print("🔍 Analyse des paquets...")
    for pkt in tqdm(packets, desc="   Traitement"):
        if not pkt.haslayer(IP):
            continue

        ip = pkt[IP]
        proto = ip.proto

        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            flags = pkt[TCP].flags
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            flags = 0
        else:
            sport = 0
            dport = 0
            flags = 0

        flow_key = (ip.src, ip.dst, proto, sport, dport)

        flows[flow_key].append({
            'time': pkt.time,
            'len': len(pkt),
            'flags': flags,
            'src_mac': pkt.src if pkt.haslayer(Ether) else None,
            'dst_mac': pkt.dst if pkt.haslayer(Ether) else None
        })

    print(f"   Flux identifiés: {len(flows)}")

    # Limiter le nombre de flux
    flow_items = list(flows.items())
    if len(flow_items) > max_flows:
        flow_items = flow_items[:max_flows]
        print(f"   Limité à {max_flows} flux")

    # Construire les vecteurs de features
    features_list = []

    print("📊 Extraction des features...")
    for flow_key, pkts in tqdm(flow_items, desc="   Flux traités"):
        if len(pkts) < 2:
            continue

        times = [p['time'] for p in pkts]
        lens = [p['len'] for p in pkts]
        flags = [p['flags'] for p in pkts]

        # Stats de base
        duration = max(times) - min(times)
        packet_count = len(pkts)
        byte_count = sum(lens)
        protocol = flow_key[2]

        # Calculs
        mean_pkt_len = byte_count / packet_count if packet_count > 0 else 0
        flow_sec = duration + 1e-9
        pkt_per_sec = packet_count / flow_sec
        byte_per_sec = byte_count / flow_sec

        # IAT (Inter-Arrival Time)
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

        # Construire le vecteur
        f = [0.0] * 82

        f[0] = duration * 1_000_000  # flow_duration (µs)
        f[1] = protocol
        f[2] = packet_count
        f[3] = 0  # bwd_pkt_count (approx)
        f[4] = byte_count
        f[5] = 0
        f[6] = mean_pkt_len
        f[7] = np.std(lens) if lens else 0
        f[8] = max(lens) if lens else 0
        f[9] = min(lens) if lens else 0
        f[14] = byte_per_sec
        f[15] = pkt_per_sec

        # IAT
        f[16] = avg_iat
        f[17] = std_iat
        f[18] = max_iat
        f[19] = min_iat
        f[20] = avg_iat
        f[21] = std_iat
        f[22] = max_iat
        f[23] = min_iat

        # Flags TCP
        f[32] = fin_count
        f[33] = syn_count
        f[34] = rst_count
        f[35] = psh_count
        f[36] = ack_count

        # Header lengths (approx)
        f[40] = packet_count * 20
        f[41] = 0

        # Packet length stats
        f[44] = min(lens) if lens else 0
        f[45] = max(lens) if lens else 0
        f[46] = mean_pkt_len
        f[47] = np.std(lens) if lens else 0
        f[48] = (np.std(lens) ** 2) if lens else 0

        # Subflow
        f[54] = packet_count
        f[55] = byte_count

        # L2/L3
        macs = set([p['src_mac'] for p in pkts if p['src_mac']])
        f[70] = len(macs) if macs else 1
        f[71] = 1

        features_list.append(f)

    print(f"   Features extraites: {len(features_list)} flux")
    return np.array(features_list)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 extract_features_from_pcap.py <pcap_file> [output_file] [sample_rate] [max_flows]")
        print("  sample_rate: 0.1 = 10% des paquets")
        print("  max_flows: nombre max de flux à extraire (défaut: 5000)")
        sys.exit(1)

    pcap_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "dataset/real_features.csv"
    sample_rate = float(sys.argv[3]) if len(sys.argv) > 3 else 0.1
    max_flows = int(sys.argv[4]) if len(sys.argv) > 4 else 5000

    if not os.path.exists(pcap_file):
        print(f"❌ Fichier introuvable: {pcap_file}")
        sys.exit(1)

    print("\\n" + "="*50)
    print("EXTRACTION DES FEATURES DU DATASET RÉEL")
    print("="*50)

    features = extract_flow_features(pcap_file, sample_rate, max_flows)

    # Sauvegarder
    df = pd.DataFrame(features, columns=COLUMNS)
    df.to_csv(output_file, index=False)
    print(f"\\n✅ Features sauvegardées: {output_file}")
    print(f"   {len(df)} flux, {len(COLUMNS)} features")

    # Statistiques
    print("\\n📊 STATISTIQUES:")
    print(f"   Durée moyenne: {df['flow_duration'].mean():.0f} µs")
    print(f"   Paquets moyen: {df['fwd_pkt_count'].mean():.0f}")
    print(f"   Bytes moyen: {df['fwd_bytes_total'].mean():.0f}")
    print(f"   SYN count moyen: {df['syn_flag_count'].mean():.0f}")

if __name__ == "__main__":
    main()
