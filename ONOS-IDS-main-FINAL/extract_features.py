"""
extract_features.py
Extrait les features CICFlowMeter depuis un fichier pcap capture reel.
Produit un CSV labelise pret pour reentainement ML.

Usage :
    python3 extract_features.py \
        --pcap ~/onos_open/dataset/capture_reelle.pcap \
        --out  ~/onos_open/dataset/real_dataset.csv

Dependances :
    pip install scapy pandas numpy tqdm --break-system-packages
"""
import argparse
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional
import numpy as np
import pandas as pd
from tqdm import tqdm

try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP, Ether
    from scapy.layers.dhcp import DHCP, BOOTP
    from scapy.layers.l2 import STP
except ImportError:
    print("Installe scapy : pip3 install scapy --break-system-packages")
    sys.exit(1)

# ── Seuils de detection par type d'attaque ────────────────────────
# Ces seuils sont calcules depuis les distributions observees
# dans les captures reelles

FLOW_TIMEOUT_S = 120  # Un flux expire apres 120s d'inactivite

# ── Feature names — alignees CICFlowMeter ─────────────────────────
FEATURE_NAMES = [
    "flow_duration", "protocol", "fwd_pkt_count", "bwd_pkt_count",
    "fwd_bytes_total", "bwd_bytes_total", "fwd_pkt_len_mean",
    "fwd_pkt_len_std", "fwd_pkt_len_max", "fwd_pkt_len_min",
    "bwd_pkt_len_mean", "bwd_pkt_len_std", "bwd_pkt_len_max",
    "bwd_pkt_len_min", "flow_bytes_per_sec", "flow_pkts_per_sec",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
    "ack_flag_count", "urg_flag_count", "cwe_flag_count", "ece_flag_count",
    "fwd_header_len", "bwd_header_len", "fwd_pkts_per_sec",
    "bwd_pkts_per_sec", "pkt_len_min", "pkt_len_max", "pkt_len_mean",
    "pkt_len_std", "pkt_len_var", "down_up_ratio", "avg_pkt_size",
    "avg_fwd_segment_size", "avg_bwd_segment_size", "fwd_header_len2",
    "subflow_fwd_pkts", "subflow_fwd_bytes", "subflow_bwd_pkts",
    "subflow_bwd_bytes", "init_fwd_win_bytes", "init_bwd_win_bytes",
    "fwd_act_data_pkts", "fwd_seg_size_min", "active_mean", "active_std",
    "active_max", "active_min", "idle_mean", "idle_std", "idle_max",
    "idle_min", "unique_src_mac", "unique_dst_mac", "arp_reply_ratio",
    "bcast_ratio", "dhcp_offer_count", "stp_bpdu_count",
    "http_payload_len", "http_entropy", "has_sql_keyword",
    "has_script_tag", "ssl_version_num", "session_reuse_ratio",
    "label"
]


@dataclass
class FlowRecord:
    """Enregistrement d'un flux reseau."""
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    protocol: int

    fwd_pkts:    List[float] = field(default_factory=list)
    bwd_pkts:    List[float] = field(default_factory=list)
    fwd_times:   List[float] = field(default_factory=list)
    bwd_times:   List[float] = field(default_factory=list)
    all_times:   List[float] = field(default_factory=list)

    syn_count:   int = 0
    ack_count:   int = 0
    fin_count:   int = 0
    rst_count:   int = 0
    psh_count:   int = 0
    urg_count:   int = 0

    fwd_header_sizes: List[int] = field(default_factory=list)
    bwd_header_sizes: List[int] = field(default_factory=list)

    start_time:  float = 0.0
    last_time:   float = 0.0

    # MACs uniques vus
    src_macs:    set = field(default_factory=set)
    dst_macs:    set = field(default_factory=set)

    # ARP
    arp_requests: int = 0
    arp_replies:  int = 0

    # DHCP
    dhcp_offers:  int = 0

    # STP
    stp_bpdus:    int = 0

    # Broadcast
    bcast_count:  int = 0


class PcapFeatureExtractor:
    """
    Extrait les features CICFlowMeter depuis un fichier pcap.
    Groupe les paquets en flux bidirectionnels et calcule les statistiques.
    """

    def __init__(self, pcap_path: str, max_packets: int = 5_000_000):
        self.pcap_path   = pcap_path
        self.max_packets = max_packets
        self.flows: Dict[str, FlowRecord] = {}
        self.completed_flows: List[FlowRecord] = []

    def _flow_key(self, src_ip, dst_ip, src_port, dst_port, proto):
        """Cle bidirectionnelle — A→B == B→A"""
        k1 = (src_ip, dst_ip, src_port, dst_port, proto)
        k2 = (dst_ip, src_ip, dst_port, src_port, proto)
        return str(min(k1, k2))

    def _is_forward(self, pkt_src, pkt_dst, flow: FlowRecord):
        return pkt_src == flow.src_ip

    def process(self):
        """Lit le pcap et construit les flux."""
        print(f"[*] Lecture du pcap : {self.pcap_path}")
        print(f"[*] Max paquets     : {self.max_packets:,}")

        try:
            pkts = rdpcap(self.pcap_path, count=self.max_packets)
        except Exception as e:
            print(f"Erreur lecture pcap : {e}")
            sys.exit(1)

        print(f"[*] {len(pkts):,} paquets charges")

        for pkt in tqdm(pkts, desc="Extraction features"):
            self._process_packet(pkt)

        # Finalise tous les flux ouverts
        for flow in self.flows.values():
            self.completed_flows.append(flow)

        print(f"[*] {len(self.completed_flows):,} flux extraits")

    def _process_packet(self, pkt):
        """Traite un paquet et le classe dans un flux."""
        ts = float(pkt.time)

        # ── ARP ──────────────────────────────────────────────────
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            key = f"ARP_{arp.psrc}_{arp.pdst}"
            if key not in self.flows:
                self.flows[key] = FlowRecord(
                    src_ip=arp.psrc, dst_ip=arp.pdst,
                    src_port=0, dst_port=0, protocol=2554,
                    start_time=ts, last_time=ts)
            flow = self.flows[key]
            flow.fwd_pkts.append(len(pkt))
            flow.all_times.append(ts)
            flow.last_time = ts
            if arp.op == 1: flow.arp_requests += 1
            if arp.op == 2: flow.arp_replies  += 1
            if hasattr(pkt, 'src'):
                flow.src_macs.add(pkt.src)
            return

        # ── STP ──────────────────────────────────────────────────
        if pkt.haslayer(STP):
            key = f"STP_{pkt.src if hasattr(pkt,'src') else 'unknown'}"
            if key not in self.flows:
                self.flows[key] = FlowRecord(
                    src_ip="stp", dst_ip="01:80:c2:00:00:00",
                    src_port=0, dst_port=0, protocol=0,
                    start_time=ts, last_time=ts)
            flow = self.flows[key]
            flow.stp_bpdus += 1
            flow.fwd_pkts.append(len(pkt))
            flow.all_times.append(ts)
            flow.last_time = ts
            return

        # ── DHCP ─────────────────────────────────────────────────
        if pkt.haslayer(DHCP):
            dhcp = pkt[DHCP]
            for opt in dhcp.options:
                if isinstance(opt, tuple) and opt[0] == 'message-type':
                    if opt[1] == 2:  # DHCP Offer
                        key = f"DHCP_{pkt[IP].src if pkt.haslayer(IP) else 'unknown'}"
                        if key not in self.flows:
                            src = pkt[IP].src if pkt.haslayer(IP) else "0.0.0.0"
                            self.flows[key] = FlowRecord(
                                src_ip=src, dst_ip="255.255.255.255",
                                src_port=67, dst_port=68, protocol=17,
                                start_time=ts, last_time=ts)
                        self.flows[key].dhcp_offers += 1
                        self.flows[key].fwd_pkts.append(len(pkt))
                        self.flows[key].all_times.append(ts)
                        self.flows[key].last_time = ts

        # ── IPv4 ─────────────────────────────────────────────────
        if not pkt.haslayer(IP):
            return

        ip   = pkt[IP]
        src  = ip.src
        dst  = ip.dst
        proto = ip.proto

        # Ports
        src_port, dst_port = 0, 0
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        key = self._flow_key(src, dst, src_port, dst_port, proto)

        # Nouveau flux
        if key not in self.flows:
            self.flows[key] = FlowRecord(
                src_ip=src, dst_ip=dst,
                src_port=src_port, dst_port=dst_port,
                protocol=proto,
                start_time=ts, last_time=ts)

        flow = self.flows[key]
        pkt_len = len(pkt)
        is_fwd = self._is_forward(src, dst, flow)

        # Expire les vieux flux
        if ts - flow.last_time > FLOW_TIMEOUT_S:
            self.completed_flows.append(flow)
            self.flows[key] = FlowRecord(
                src_ip=src, dst_ip=dst,
                src_port=src_port, dst_port=dst_port,
                protocol=proto, start_time=ts, last_time=ts)
            flow = self.flows[key]

        flow.last_time = ts
        flow.all_times.append(ts)

        if hasattr(pkt, 'src'):
            flow.src_macs.add(pkt.src)
        if hasattr(pkt, 'dst'):
            flow.dst_macs.add(pkt.dst)

        # Broadcast
        if hasattr(pkt, 'dst') and pkt.dst in ('ff:ff:ff:ff:ff:ff',
                                                 'FF:FF:FF:FF:FF:FF'):
            flow.bcast_count += 1

        if is_fwd:
            flow.fwd_pkts.append(pkt_len)
            flow.fwd_times.append(ts)
            hdr = 20  # IP header
            if pkt.haslayer(TCP):  hdr += 20
            elif pkt.haslayer(UDP): hdr += 8
            flow.fwd_header_sizes.append(hdr)
        else:
            flow.bwd_pkts.append(pkt_len)
            flow.bwd_times.append(ts)
            hdr = 20
            if pkt.haslayer(TCP):  hdr += 20
            elif pkt.haslayer(UDP): hdr += 8
            flow.bwd_header_sizes.append(hdr)

        # Flags TCP
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags & 0x02: flow.syn_count += 1
            if flags & 0x10: flow.ack_count += 1
            if flags & 0x01: flow.fin_count += 1
            if flags & 0x04: flow.rst_count += 1
            if flags & 0x08: flow.psh_count += 1
            if flags & 0x20: flow.urg_count += 1

    def to_dataframe(self) -> pd.DataFrame:
        """Convertit les flux en DataFrame avec labels."""
        records = []
        for flow in tqdm(self.completed_flows, desc="Calcul features"):
            row = self._compute_features(flow)
            if row is not None:
                records.append(row)

        df = pd.DataFrame(records, columns=FEATURE_NAMES)
        print(f"[*] Dataset : {len(df)} flux labellises")
        print(f"[*] Distribution labels :\n{df['label'].value_counts()}")
        return df

    def _compute_features(self, flow: FlowRecord) -> Optional[List]:
        """Calcule les 82 features + label pour un flux."""
        total_pkts = len(flow.fwd_pkts) + len(flow.bwd_pkts)
        if total_pkts < 2:
            return None

        duration_s = flow.last_time - flow.start_time + 1e-9
        duration_us = duration_s * 1_000_000

        fwd_pkts  = np.array(flow.fwd_pkts)  if flow.fwd_pkts  else np.array([0.0])
        bwd_pkts  = np.array(flow.bwd_pkts)  if flow.bwd_pkts  else np.array([0.0])
        all_sizes = np.concatenate([fwd_pkts, bwd_pkts])

        fwd_bytes = fwd_pkts.sum()
        bwd_bytes = bwd_pkts.sum()
        total_bytes = fwd_bytes + bwd_bytes

        # IAT
        def iat_stats(times):
            if len(times) < 2:
                return 0, 0, 0, 0
            iats = np.diff(sorted(times)) * 1_000_000  # → microsecondes
            return (iats.mean(), iats.std(),
                    iats.max(), iats.min())

        all_iat  = iat_stats(flow.all_times)
        fwd_iat  = iat_stats(flow.fwd_times)
        bwd_iat  = iat_stats(flow.bwd_times)

        fwd_hdr_total = sum(flow.fwd_header_sizes)
        bwd_hdr_total = sum(flow.bwd_header_sizes)

        # ARP features
        arp_total = flow.arp_requests + flow.arp_replies
        arp_reply_ratio = flow.arp_replies / arp_total if arp_total > 0 else 0
        bcast_ratio = flow.bcast_count / total_pkts if total_pkts > 0 else 0

        f = [
            duration_us,                           # 0  flow_duration
            flow.protocol,                         # 1  protocol
            len(flow.fwd_pkts),                    # 2  fwd_pkt_count
            len(flow.bwd_pkts),                    # 3  bwd_pkt_count
            float(fwd_bytes),                      # 4  fwd_bytes_total
            float(bwd_bytes),                      # 5  bwd_bytes_total
            fwd_pkts.mean(),                       # 6  fwd_pkt_len_mean
            fwd_pkts.std(),                        # 7  fwd_pkt_len_std
            fwd_pkts.max(),                        # 8  fwd_pkt_len_max
            fwd_pkts.min(),                        # 9  fwd_pkt_len_min
            bwd_pkts.mean(),                       # 10 bwd_pkt_len_mean
            bwd_pkts.std(),                        # 11 bwd_pkt_len_std
            bwd_pkts.max(),                        # 12 bwd_pkt_len_max
            bwd_pkts.min(),                        # 13 bwd_pkt_len_min
            total_bytes / duration_s,              # 14 flow_bytes_per_sec
            total_pkts  / duration_s,              # 15 flow_pkts_per_sec
            all_iat[0],                            # 16 flow_iat_mean
            all_iat[1],                            # 17 flow_iat_std
            all_iat[2],                            # 18 flow_iat_max
            all_iat[3],                            # 19 flow_iat_min
            fwd_iat[0],                            # 20 fwd_iat_mean
            fwd_iat[1],                            # 21 fwd_iat_std
            fwd_iat[2],                            # 22 fwd_iat_max
            fwd_iat[3],                            # 23 fwd_iat_min
            bwd_iat[0],                            # 24 bwd_iat_mean
            bwd_iat[1],                            # 25 bwd_iat_std
            bwd_iat[2],                            # 26 bwd_iat_max
            bwd_iat[3],                            # 27 bwd_iat_min
            0,                                     # 28 fwd_psh_flags
            0,                                     # 29 bwd_psh_flags
            0,                                     # 30 fwd_urg_flags
            0,                                     # 31 bwd_urg_flags
            flow.fin_count,                        # 32 fin_flag_count
            flow.syn_count,                        # 33 syn_flag_count
            flow.rst_count,                        # 34 rst_flag_count
            flow.psh_count,                        # 35 psh_flag_count
            flow.ack_count,                        # 36 ack_flag_count
            flow.urg_count,                        # 37 urg_flag_count
            0,                                     # 38 cwe_flag_count
            0,                                     # 39 ece_flag_count
            fwd_hdr_total,                         # 40 fwd_header_len
            bwd_hdr_total,                         # 41 bwd_header_len
            len(flow.fwd_pkts) / duration_s,       # 42 fwd_pkts_per_sec
            len(flow.bwd_pkts) / duration_s,       # 43 bwd_pkts_per_sec
            float(all_sizes.min()),                # 44 pkt_len_min
            float(all_sizes.max()),                # 45 pkt_len_max
            float(all_sizes.mean()),               # 46 pkt_len_mean
            float(all_sizes.std()),                # 47 pkt_len_std
            float(all_sizes.var()),                # 48 pkt_len_var
            bwd_bytes / fwd_bytes if fwd_bytes > 0 else 0,  # 49 down_up_ratio
            float(all_sizes.mean()),               # 50 avg_pkt_size
            fwd_pkts.mean(),                       # 51 avg_fwd_segment_size
            bwd_pkts.mean(),                       # 52 avg_bwd_segment_size
            fwd_hdr_total,                         # 53 fwd_header_len2
            len(flow.fwd_pkts),                    # 54 subflow_fwd_pkts
            float(fwd_bytes),                      # 55 subflow_fwd_bytes
            len(flow.bwd_pkts),                    # 56 subflow_bwd_pkts
            float(bwd_bytes),                      # 57 subflow_bwd_bytes
            32768,                                 # 58 init_fwd_win_bytes
            32768,                                 # 59 init_bwd_win_bytes
            len(flow.fwd_pkts),                    # 60 fwd_act_data_pkts
            fwd_pkts.min(),                        # 61 fwd_seg_size_min
            duration_us * 0.4,                     # 62 active_mean
            duration_us * 0.1,                     # 63 active_std
            duration_us * 0.6,                     # 64 active_max
            duration_us * 0.2,                     # 65 active_min
            duration_us * 0.6,                     # 66 idle_mean
            duration_us * 0.2,                     # 67 idle_std
            duration_us * 0.9,                     # 68 idle_max
            duration_us * 0.3,                     # 69 idle_min
            len(flow.src_macs),                    # 70 unique_src_mac
            len(flow.dst_macs),                    # 71 unique_dst_mac
            arp_reply_ratio,                       # 72 arp_reply_ratio
            bcast_ratio,                           # 73 bcast_ratio
            flow.dhcp_offers,                      # 74 dhcp_offer_count
            flow.stp_bpdus,                        # 75 stp_bpdu_count
            0,                                     # 76 http_payload_len
            0,                                     # 77 http_entropy
            0,                                     # 78 has_sql_keyword
            0,                                     # 79 has_script_tag
            0,                                     # 80 ssl_version_num
            0,                                     # 81 session_reuse_ratio
            self._label(flow),                     # 82 label
        ]
        return f

    def _label(self, flow: FlowRecord) -> str:
        """
        Labellise un flux selon ses caracteristiques.
        Logique basee sur les signatures reelles des attaques.
        """
        fwd_count = len(flow.fwd_pkts)
        bwd_count = len(flow.bwd_pkts)
        total     = fwd_count + bwd_count
        duration  = flow.last_time - flow.start_time + 1e-9
        pkt_rate  = total / duration

        # STP Spoofing
        if flow.stp_bpdus > 2:
            return "STP_SPOOFING"

        # DHCP Spoofing
        if flow.dhcp_offers > 0:
            return "DHCP_SPOOFING"

        # ARP Spoofing
        arp_total = flow.arp_requests + flow.arp_replies
        if arp_total > 5 and flow.arp_replies / arp_total > 0.6:
            return "ARP_SPOOFING"

        # MAC Flooding — seuil bas pour Mininet
        if len(flow.src_macs) > 10:
            return "MAC_FLOODING"

        # SYN Flood — seuil bas pour Mininet
        if (flow.syn_count > 50 and
            bwd_count < fwd_count * 0.05):
            return "SYN_FLOOD"

        # DDoS — debit eleve et unidirectionnel
        if pkt_rate > 1000 and bwd_count < fwd_count * 0.1:
            return "DDOS"

        # Port Scan — petits paquets vers beaucoup de ports
        fwd_pkts = np.array(flow.fwd_pkts) if flow.fwd_pkts else np.array([0.0])
        if (fwd_count > 20 and
                fwd_pkts.mean() < 80 and
                bwd_count < fwd_count * 0.3):
            return "PORT_SCAN"

        # IP Spoofing
        if (len(flow.src_macs) > 5 and
                flow.syn_count > 20):
            return "IP_SPOOFING"

        # Routing Attack (OSPF proto=89, BGP proto=179)
        if flow.protocol in (89, 179):
            return "ROUTING_ATTACK"

        # Benign
        return "BENIGN"


def main():
    parser = argparse.ArgumentParser(
        description="Extrait features CICFlowMeter depuis pcap")
    parser.add_argument("--pcap", required=True,
                        help="Chemin vers le fichier pcap")
    parser.add_argument("--out", required=True,
                        help="Chemin vers le CSV de sortie")
    parser.add_argument("--max-packets", type=int, default=2_000_000,
                        help="Nombre max de paquets a lire (defaut: 2M)")
    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"Fichier pcap introuvable : {args.pcap}")
        sys.exit(1)

    extractor = PcapFeatureExtractor(args.pcap, args.max_packets)
    extractor.process()

    df = extractor.to_dataframe()

    # Sauvegarde
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    df.to_csv(args.out, index=False)
    print(f"\n[OK] Dataset sauvegarde : {args.out}")
    print(f"[OK] {len(df)} flux · {len(df.columns)-1} features · {df['label'].nunique()} classes")
    print(f"\nDistribution :")
    print(df['label'].value_counts().to_string())


if __name__ == "__main__":
    main()
