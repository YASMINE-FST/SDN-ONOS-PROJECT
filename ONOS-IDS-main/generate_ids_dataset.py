"""
IDS Dataset Generator — ONOS AI Security Project
Génère ~15 000 flux réseau synthétiques réalistes pour 14 classes d'attaques + BENIGN.

Features alignées sur CICFlowMeter (78 features) pour compatibilité maximale.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder
import warnings
warnings.filterwarnings("ignore")

RNG = np.random.default_rng(42)

# ─────────────────────────────────────────────
# FEATURE COLUMNS (78 features CICFlowMeter-like)
# ─────────────────────────────────────────────
COLUMNS = [
    # Identifiants de flux
    "flow_duration", "protocol",
    # Paquets forward/backward
    "fwd_pkt_count", "bwd_pkt_count",
    "fwd_bytes_total", "bwd_bytes_total",
    "fwd_pkt_len_mean", "fwd_pkt_len_std", "fwd_pkt_len_max", "fwd_pkt_len_min",
    "bwd_pkt_len_mean", "bwd_pkt_len_std", "bwd_pkt_len_max", "bwd_pkt_len_min",
    # Flow rates
    "flow_bytes_per_sec", "flow_pkts_per_sec",
    # Inter-Arrival Time (IAT)
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
    "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min",
    "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min",
    # TCP Flags
    "fwd_psh_flags", "bwd_psh_flags",
    "fwd_urg_flags", "bwd_urg_flags",
    "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "psh_flag_count", "ack_flag_count", "urg_flag_count",
    "cwe_flag_count", "ece_flag_count",
    # Header sizes
    "fwd_header_len", "bwd_header_len",
    # Bulk features
    "fwd_pkts_per_sec", "bwd_pkts_per_sec",
    "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    # Payload
    "down_up_ratio", "avg_pkt_size", "avg_fwd_segment_size", "avg_bwd_segment_size",
    "fwd_header_len2",
    # Subflow
    "subflow_fwd_pkts", "subflow_fwd_bytes", "subflow_bwd_pkts", "subflow_bwd_bytes",
    # Init window bytes
    "init_fwd_win_bytes", "init_bwd_win_bytes",
    "fwd_act_data_pkts", "fwd_seg_size_min",
    # Active/Idle
    "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
    # Layer 2/3 specific
    "unique_src_mac", "unique_dst_mac", "arp_reply_ratio", "bcast_ratio",
    "dhcp_offer_count", "stp_bpdu_count",
    # L7 features
    "http_payload_len", "http_entropy", "has_sql_keyword", "has_script_tag",
    "ssl_version_num", "session_reuse_ratio",
    # Label
    "label"
]

N = len(COLUMNS)

def clip(arr, lo, hi):
    return np.clip(arr, lo, hi)

def rng_int(lo, hi, size):
    return RNG.integers(lo, hi, size=size)

def rng_float(lo, hi, size):
    return RNG.uniform(lo, hi, size=size)

def rng_normal(mean, std, size, lo=0, hi=None):
    arr = RNG.normal(mean, std, size=size)
    arr = np.maximum(arr, lo)
    if hi is not None:
        arr = np.minimum(arr, hi)
    return arr

# ─────────────────────────────────────────────────────────────
# BENIGN
# ─────────────────────────────────────────────────────────────
def gen_benign(n=5000):
    d = {}
    d["flow_duration"]       = rng_normal(500000, 300000, n, 100, 5000000)
    d["protocol"]            = RNG.choice([6, 17, 1], n, p=[0.7, 0.25, 0.05])
    d["fwd_pkt_count"]       = rng_normal(20, 15, n, 1, 200)
    d["bwd_pkt_count"]       = rng_normal(18, 14, n, 0, 200)
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * rng_normal(500, 200, n, 40)
    d["bwd_bytes_total"]     = d["bwd_pkt_count"] * rng_normal(480, 200, n, 0)
    d["fwd_pkt_len_mean"]    = rng_normal(500, 200, n, 40, 1500)
    d["fwd_pkt_len_std"]     = rng_normal(150, 80, n, 0, 600)
    d["fwd_pkt_len_max"]     = d["fwd_pkt_len_mean"] + rng_normal(300, 100, n, 0, 1000)
    d["fwd_pkt_len_min"]     = np.maximum(0, d["fwd_pkt_len_mean"] - rng_normal(200, 80, n, 0))
    d["bwd_pkt_len_mean"]    = rng_normal(480, 200, n, 0, 1500)
    d["bwd_pkt_len_std"]     = rng_normal(140, 80, n, 0, 600)
    d["bwd_pkt_len_max"]     = d["bwd_pkt_len_mean"] + rng_normal(280, 100, n, 0)
    d["bwd_pkt_len_min"]     = np.maximum(0, d["bwd_pkt_len_mean"] - rng_normal(180, 80, n, 0))
    d["flow_bytes_per_sec"]  = (d["fwd_bytes_total"] + d["bwd_bytes_total"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = (d["fwd_pkt_count"] + d["bwd_pkt_count"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(30000, 20000, n, 100, 500000)
    d["flow_iat_std"]        = rng_normal(15000, 10000, n, 0, 300000)
    d["flow_iat_max"]        = d["flow_iat_mean"] + rng_normal(50000, 20000, n, 0)
    d["flow_iat_min"]        = np.maximum(0, d["flow_iat_mean"] - rng_normal(20000, 8000, n, 0))
    d["fwd_iat_mean"]        = rng_normal(32000, 20000, n, 100)
    d["fwd_iat_std"]         = rng_normal(16000, 10000, n, 0)
    d["fwd_iat_max"]         = d["fwd_iat_mean"] + rng_normal(50000, 20000, n, 0)
    d["fwd_iat_min"]         = np.maximum(0, d["fwd_iat_mean"] - rng_normal(20000, 8000, n, 0))
    d["bwd_iat_mean"]        = rng_normal(31000, 19000, n, 100)
    d["bwd_iat_std"]         = rng_normal(15000, 9000, n, 0)
    d["bwd_iat_max"]         = d["bwd_iat_mean"] + rng_normal(48000, 18000, n, 0)
    d["bwd_iat_min"]         = np.maximum(0, d["bwd_iat_mean"] - rng_normal(19000, 7000, n, 0))
    d["fwd_psh_flags"]       = rng_int(0, 5, n)
    d["bwd_psh_flags"]       = rng_int(0, 5, n)
    d["fwd_urg_flags"]       = np.zeros(n)
    d["bwd_urg_flags"]       = np.zeros(n)
    d["fin_flag_count"]      = rng_int(0, 2, n)
    d["syn_flag_count"]      = rng_int(1, 3, n)
    d["rst_flag_count"]      = rng_int(0, 1, n)
    d["psh_flag_count"]      = rng_int(0, 8, n)
    d["ack_flag_count"]      = d["fwd_pkt_count"] + d["bwd_pkt_count"] - rng_int(0, 3, n)
    d["urg_flag_count"]      = np.zeros(n)
    d["cwe_flag_count"]      = np.zeros(n)
    d["ece_flag_count"]      = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 20
    d["bwd_header_len"]      = d["bwd_pkt_count"] * 20
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = d["bwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["pkt_len_min"]         = d["fwd_pkt_len_min"]
    d["pkt_len_max"]         = np.maximum(d["fwd_pkt_len_max"], d["bwd_pkt_len_max"])
    d["pkt_len_mean"]        = (d["fwd_pkt_len_mean"] + d["bwd_pkt_len_mean"]) / 2
    d["pkt_len_std"]         = (d["fwd_pkt_len_std"] + d["bwd_pkt_len_std"]) / 2
    d["pkt_len_var"]         = d["pkt_len_std"] ** 2
    d["down_up_ratio"]       = d["bwd_bytes_total"] / (d["fwd_bytes_total"] + 1)
    d["avg_pkt_size"]        = d["pkt_len_mean"]
    d["avg_fwd_segment_size"]= d["fwd_pkt_len_mean"]
    d["avg_bwd_segment_size"]= d["bwd_pkt_len_mean"]
    d["fwd_header_len2"]     = d["fwd_header_len"]
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"]
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"]
    d["subflow_bwd_pkts"]    = d["bwd_pkt_count"]
    d["subflow_bwd_bytes"]   = d["bwd_bytes_total"]
    d["init_fwd_win_bytes"]  = rng_int(8192, 65536, n)
    d["init_bwd_win_bytes"]  = rng_int(8192, 65536, n)
    d["fwd_act_data_pkts"]   = d["fwd_pkt_count"] - rng_int(0, 3, n)
    d["fwd_seg_size_min"]    = d["fwd_pkt_len_min"]
    d["active_mean"]         = rng_normal(200000, 100000, n, 0)
    d["active_std"]          = rng_normal(80000, 40000, n, 0)
    d["active_max"]          = d["active_mean"] + rng_normal(150000, 60000, n, 0)
    d["active_min"]          = np.maximum(0, d["active_mean"] - rng_normal(100000, 40000, n, 0))
    d["idle_mean"]           = rng_normal(1000000, 500000, n, 0)
    d["idle_std"]            = rng_normal(400000, 200000, n, 0)
    d["idle_max"]            = d["idle_mean"] + rng_normal(800000, 300000, n, 0)
    d["idle_min"]            = np.maximum(0, d["idle_mean"] - rng_normal(500000, 200000, n, 0))
    # L2/L3
    d["unique_src_mac"]      = np.ones(n)
    d["unique_dst_mac"]      = np.ones(n)
    d["arp_reply_ratio"]     = rng_float(0.0, 0.1, n)
    d["bcast_ratio"]         = rng_float(0.0, 0.05, n)
    d["dhcp_offer_count"]    = np.zeros(n)
    d["stp_bpdu_count"]      = rng_int(0, 2, n)
    # L7
    d["http_payload_len"]    = rng_normal(1200, 600, n, 0, 8000)
    d["http_entropy"]        = rng_normal(4.5, 0.8, n, 0, 8)
    d["has_sql_keyword"]     = np.zeros(n)
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = RNG.choice([12, 13], n, p=[0.2, 0.8])
    d["session_reuse_ratio"] = rng_float(0.0, 0.3, n)
    d["label"]               = np.full(n, "BENIGN")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# ARP SPOOFING
# ─────────────────────────────────────────────────────────────
def gen_arp_spoofing(n=800):
    d = {}
    d["flow_duration"]       = rng_normal(2000000, 1000000, n, 100000, 10000000)
    d["protocol"]            = np.full(n, 2554)   # ARP EtherType 0x0806
    d["fwd_pkt_count"]       = rng_normal(300, 100, n, 50, 2000)
    d["bwd_pkt_count"]       = np.zeros(n)
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * 42   # ARP = 42 bytes
    d["bwd_bytes_total"]     = np.zeros(n)
    d["fwd_pkt_len_mean"]    = np.full(n, 42.0)
    d["fwd_pkt_len_std"]     = np.zeros(n)
    d["fwd_pkt_len_max"]     = np.full(n, 42.0)
    d["fwd_pkt_len_min"]     = np.full(n, 42.0)
    d["bwd_pkt_len_mean"]    = np.zeros(n)
    d["bwd_pkt_len_std"]     = np.zeros(n)
    d["bwd_pkt_len_max"]     = np.zeros(n)
    d["bwd_pkt_len_min"]     = np.zeros(n)
    d["flow_bytes_per_sec"]  = d["fwd_bytes_total"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(500, 200, n, 10, 5000)   # rafale rapide
    d["flow_iat_std"]        = rng_normal(200, 100, n, 0)
    d["flow_iat_max"]        = d["flow_iat_mean"] + rng_normal(1000, 400, n, 0)
    d["flow_iat_min"]        = np.maximum(0, d["flow_iat_mean"] - rng_normal(400, 150, n, 0))
    d["fwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["fwd_iat_std"]         = d["flow_iat_std"].copy()
    d["fwd_iat_max"]         = d["flow_iat_max"].copy()
    d["fwd_iat_min"]         = d["flow_iat_min"].copy()
    d["bwd_iat_mean"]        = np.zeros(n)
    d["bwd_iat_std"]         = np.zeros(n)
    d["bwd_iat_max"]         = np.zeros(n)
    d["bwd_iat_min"]         = np.zeros(n)
    d["fwd_psh_flags"]       = np.zeros(n)
    d["bwd_psh_flags"]       = np.zeros(n)
    d["fwd_urg_flags"]       = np.zeros(n)
    d["bwd_urg_flags"]       = np.zeros(n)
    d["fin_flag_count"]      = np.zeros(n)
    d["syn_flag_count"]      = np.zeros(n)
    d["rst_flag_count"]      = np.zeros(n)
    d["psh_flag_count"]      = np.zeros(n)
    d["ack_flag_count"]      = np.zeros(n)
    d["urg_flag_count"]      = np.zeros(n)
    d["cwe_flag_count"]      = np.zeros(n)
    d["ece_flag_count"]      = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 14   # Ethernet header
    d["bwd_header_len"]      = np.zeros(n)
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = np.zeros(n)
    d["pkt_len_min"]         = np.full(n, 42.0)
    d["pkt_len_max"]         = np.full(n, 42.0)
    d["pkt_len_mean"]        = np.full(n, 42.0)
    d["pkt_len_std"]         = np.zeros(n)
    d["pkt_len_var"]         = np.zeros(n)
    d["down_up_ratio"]       = np.zeros(n)
    d["avg_pkt_size"]        = np.full(n, 42.0)
    d["avg_fwd_segment_size"]= np.full(n, 42.0)
    d["avg_bwd_segment_size"]= np.zeros(n)
    d["fwd_header_len2"]     = d["fwd_header_len"].copy()
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"].copy()
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"].copy()
    d["subflow_bwd_pkts"]    = np.zeros(n)
    d["subflow_bwd_bytes"]   = np.zeros(n)
    d["init_fwd_win_bytes"]  = np.zeros(n)
    d["init_bwd_win_bytes"]  = np.zeros(n)
    d["fwd_act_data_pkts"]   = d["fwd_pkt_count"].copy()
    d["fwd_seg_size_min"]    = np.full(n, 42.0)
    d["active_mean"]         = np.zeros(n)
    d["active_std"]          = np.zeros(n)
    d["active_max"]          = np.zeros(n)
    d["active_min"]          = np.zeros(n)
    d["idle_mean"]           = np.zeros(n)
    d["idle_std"]            = np.zeros(n)
    d["idle_max"]            = np.zeros(n)
    d["idle_min"]            = np.zeros(n)
    # Signature ARP Spoofing : beaucoup de replies, broadcast élevé, 1 seule MAC source
    d["unique_src_mac"]      = np.ones(n)
    d["unique_dst_mac"]      = rng_int(1, 5, n)
    d["arp_reply_ratio"]     = rng_float(0.85, 1.0, n)   # quasi 100% replies
    d["bcast_ratio"]         = rng_float(0.7, 1.0, n)    # broadcast dominant
    d["dhcp_offer_count"]    = np.zeros(n)
    d["stp_bpdu_count"]      = np.zeros(n)
    d["http_payload_len"]    = np.zeros(n)
    d["http_entropy"]        = np.zeros(n)
    d["has_sql_keyword"]     = np.zeros(n)
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = np.zeros(n)
    d["session_reuse_ratio"] = np.zeros(n)
    d["label"]               = np.full(n, "ARP_SPOOFING")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# STP SPOOFING
# ─────────────────────────────────────────────────────────────
def gen_stp_spoofing(n=400):
    d = {}
    d["flow_duration"]       = rng_normal(30000000, 10000000, n, 5000000)
    d["protocol"]            = np.full(n, 0x8100)  # 802.1Q / STP
    d["fwd_pkt_count"]       = rng_normal(50, 20, n, 10, 200)
    d["bwd_pkt_count"]       = np.zeros(n)
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * 60
    d["bwd_bytes_total"]     = np.zeros(n)
    d["fwd_pkt_len_mean"]    = rng_normal(60, 5, n, 50, 80)
    d["fwd_pkt_len_std"]     = rng_normal(3, 1, n, 0, 10)
    d["fwd_pkt_len_max"]     = d["fwd_pkt_len_mean"] + 10
    d["fwd_pkt_len_min"]     = d["fwd_pkt_len_mean"] - 5
    d["bwd_pkt_len_mean"]    = np.zeros(n)
    d["bwd_pkt_len_std"]     = np.zeros(n)
    d["bwd_pkt_len_max"]     = np.zeros(n)
    d["bwd_pkt_len_min"]     = np.zeros(n)
    d["flow_bytes_per_sec"]  = d["fwd_bytes_total"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(2000000, 500000, n, 100000)  # ~2s entre BPDUs
    d["flow_iat_std"]        = rng_normal(100000, 50000, n, 0)
    d["flow_iat_max"]        = d["flow_iat_mean"] * 1.5
    d["flow_iat_min"]        = d["flow_iat_mean"] * 0.5
    d["fwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["fwd_iat_std"]         = d["flow_iat_std"].copy()
    d["fwd_iat_max"]         = d["flow_iat_max"].copy()
    d["fwd_iat_min"]         = d["flow_iat_min"].copy()
    d["bwd_iat_mean"]        = np.zeros(n)
    d["bwd_iat_std"]         = np.zeros(n)
    d["bwd_iat_max"]         = np.zeros(n)
    d["bwd_iat_min"]         = np.zeros(n)
    for f in ["fwd_psh_flags","bwd_psh_flags","fwd_urg_flags","bwd_urg_flags",
              "fin_flag_count","syn_flag_count","rst_flag_count","psh_flag_count",
              "ack_flag_count","urg_flag_count","cwe_flag_count","ece_flag_count"]:
        d[f] = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 14
    d["bwd_header_len"]      = np.zeros(n)
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = np.zeros(n)
    d["pkt_len_min"]         = d["fwd_pkt_len_min"].copy()
    d["pkt_len_max"]         = d["fwd_pkt_len_max"].copy()
    d["pkt_len_mean"]        = d["fwd_pkt_len_mean"].copy()
    d["pkt_len_std"]         = d["fwd_pkt_len_std"].copy()
    d["pkt_len_var"]         = d["pkt_len_std"] ** 2
    d["down_up_ratio"]       = np.zeros(n)
    d["avg_pkt_size"]        = d["fwd_pkt_len_mean"].copy()
    d["avg_fwd_segment_size"]= d["fwd_pkt_len_mean"].copy()
    d["avg_bwd_segment_size"]= np.zeros(n)
    d["fwd_header_len2"]     = d["fwd_header_len"].copy()
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"].copy()
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"].copy()
    d["subflow_bwd_pkts"]    = np.zeros(n)
    d["subflow_bwd_bytes"]   = np.zeros(n)
    d["init_fwd_win_bytes"]  = np.zeros(n)
    d["init_bwd_win_bytes"]  = np.zeros(n)
    d["fwd_act_data_pkts"]   = d["fwd_pkt_count"].copy()
    d["fwd_seg_size_min"]    = d["fwd_pkt_len_min"].copy()
    d["active_mean"]         = np.zeros(n)
    d["active_std"]          = np.zeros(n)
    d["active_max"]          = np.zeros(n)
    d["active_min"]          = np.zeros(n)
    d["idle_mean"]           = np.zeros(n)
    d["idle_std"]            = np.zeros(n)
    d["idle_max"]            = np.zeros(n)
    d["idle_min"]            = np.zeros(n)
    # Signature STP : beaucoup de BPDUs, priority=0 (attaquant veut être root)
    d["unique_src_mac"]      = np.ones(n)
    d["unique_dst_mac"]      = np.ones(n)
    d["arp_reply_ratio"]     = np.zeros(n)
    d["bcast_ratio"]         = rng_float(0.9, 1.0, n)
    d["dhcp_offer_count"]    = np.zeros(n)
    d["stp_bpdu_count"]      = rng_normal(45, 15, n, 10, 200)  # BPDU count élevé
    d["http_payload_len"]    = np.zeros(n)
    d["http_entropy"]        = np.zeros(n)
    d["has_sql_keyword"]     = np.zeros(n)
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = np.zeros(n)
    d["session_reuse_ratio"] = np.zeros(n)
    d["label"]               = np.full(n, "STP_SPOOFING")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# MAC FLOODING
# ─────────────────────────────────────────────────────────────
def gen_mac_flooding(n=900):
    d = {}
    d["flow_duration"]       = rng_normal(5000000, 2000000, n, 500000)
    d["protocol"]            = np.full(n, 6)
    d["fwd_pkt_count"]       = rng_normal(5000, 2000, n, 1000, 50000)
    d["bwd_pkt_count"]       = rng_normal(10, 5, n, 0, 50)
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * rng_normal(64, 10, n, 60, 128)
    d["bwd_bytes_total"]     = d["bwd_pkt_count"] * 64
    d["fwd_pkt_len_mean"]    = rng_normal(64, 10, n, 60, 128)
    d["fwd_pkt_len_std"]     = rng_normal(5, 2, n, 0, 20)
    d["fwd_pkt_len_max"]     = np.minimum(1500, d["fwd_pkt_len_mean"] + 50)
    d["fwd_pkt_len_min"]     = np.maximum(60, d["fwd_pkt_len_mean"] - 10)
    d["bwd_pkt_len_mean"]    = rng_normal(64, 10, n, 0, 128)
    d["bwd_pkt_len_std"]     = rng_normal(5, 2, n, 0)
    d["bwd_pkt_len_max"]     = np.minimum(128, d["bwd_pkt_len_mean"] + 30)
    d["bwd_pkt_len_min"]     = np.maximum(0, d["bwd_pkt_len_mean"] - 20)
    d["flow_bytes_per_sec"]  = (d["fwd_bytes_total"] + d["bwd_bytes_total"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = (d["fwd_pkt_count"] + d["bwd_pkt_count"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(200, 100, n, 10, 2000)  # très rapide
    d["flow_iat_std"]        = rng_normal(80, 40, n, 0)
    d["flow_iat_max"]        = d["flow_iat_mean"] + rng_normal(400, 200, n, 0)
    d["flow_iat_min"]        = np.maximum(1, d["flow_iat_mean"] - rng_normal(100, 50, n, 0))
    d["fwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["fwd_iat_std"]         = d["flow_iat_std"].copy()
    d["fwd_iat_max"]         = d["flow_iat_max"].copy()
    d["fwd_iat_min"]         = d["flow_iat_min"].copy()
    d["bwd_iat_mean"]        = rng_normal(10000, 5000, n, 0)
    d["bwd_iat_std"]         = rng_normal(3000, 1000, n, 0)
    d["bwd_iat_max"]         = d["bwd_iat_mean"] + 10000
    d["bwd_iat_min"]         = np.maximum(0, d["bwd_iat_mean"] - 5000)
    d["fwd_psh_flags"]       = rng_int(0, 3, n)
    d["bwd_psh_flags"]       = np.zeros(n)
    d["fwd_urg_flags"]       = np.zeros(n)
    d["bwd_urg_flags"]       = np.zeros(n)
    d["fin_flag_count"]      = rng_int(0, 1, n)
    d["syn_flag_count"]      = rng_int(0, 3, n)
    d["rst_flag_count"]      = rng_int(0, 2, n)
    d["psh_flag_count"]      = rng_int(0, 5, n)
    d["ack_flag_count"]      = d["fwd_pkt_count"] * 0.1
    d["urg_flag_count"]      = np.zeros(n)
    d["cwe_flag_count"]      = np.zeros(n)
    d["ece_flag_count"]      = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 14
    d["bwd_header_len"]      = d["bwd_pkt_count"] * 14
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = d["bwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["pkt_len_min"]         = d["fwd_pkt_len_min"].copy()
    d["pkt_len_max"]         = d["fwd_pkt_len_max"].copy()
    d["pkt_len_mean"]        = d["fwd_pkt_len_mean"].copy()
    d["pkt_len_std"]         = d["fwd_pkt_len_std"].copy()
    d["pkt_len_var"]         = d["pkt_len_std"] ** 2
    d["down_up_ratio"]       = d["bwd_bytes_total"] / (d["fwd_bytes_total"] + 1)
    d["avg_pkt_size"]        = d["pkt_len_mean"].copy()
    d["avg_fwd_segment_size"]= d["fwd_pkt_len_mean"].copy()
    d["avg_bwd_segment_size"]= d["bwd_pkt_len_mean"].copy()
    d["fwd_header_len2"]     = d["fwd_header_len"].copy()
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"].copy()
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"].copy()
    d["subflow_bwd_pkts"]    = d["bwd_pkt_count"].copy()
    d["subflow_bwd_bytes"]   = d["bwd_bytes_total"].copy()
    d["init_fwd_win_bytes"]  = rng_int(512, 4096, n)
    d["init_bwd_win_bytes"]  = rng_int(512, 4096, n)
    d["fwd_act_data_pkts"]   = d["fwd_pkt_count"].copy()
    d["fwd_seg_size_min"]    = d["fwd_pkt_len_min"].copy()
    d["active_mean"]         = rng_normal(100000, 50000, n, 0)
    d["active_std"]          = rng_normal(30000, 15000, n, 0)
    d["active_max"]          = d["active_mean"] + 100000
    d["active_min"]          = np.maximum(0, d["active_mean"] - 50000)
    d["idle_mean"]           = rng_normal(200000, 100000, n, 0)
    d["idle_std"]            = rng_normal(80000, 40000, n, 0)
    d["idle_max"]            = d["idle_mean"] + 300000
    d["idle_min"]            = np.maximum(0, d["idle_mean"] - 100000)
    # Signature MAC Flooding : énorme quantité de MACs sources uniques
    d["unique_src_mac"]      = rng_normal(5000, 2000, n, 500, 65536)  # clé discriminante
    d["unique_dst_mac"]      = rng_int(1, 10, n)
    d["arp_reply_ratio"]     = rng_float(0.0, 0.1, n)
    d["bcast_ratio"]         = rng_float(0.3, 0.8, n)
    d["dhcp_offer_count"]    = np.zeros(n)
    d["stp_bpdu_count"]      = np.zeros(n)
    d["http_payload_len"]    = np.zeros(n)
    d["http_entropy"]        = np.zeros(n)
    d["has_sql_keyword"]     = np.zeros(n)
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = np.zeros(n)
    d["session_reuse_ratio"] = np.zeros(n)
    d["label"]               = np.full(n, "MAC_FLOODING")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# DHCP SPOOFING
# ─────────────────────────────────────────────────────────────
def gen_dhcp_spoofing(n=600):
    d = {}
    d["flow_duration"]       = rng_normal(500000, 200000, n, 50000)
    d["protocol"]            = np.full(n, 17)  # UDP
    d["fwd_pkt_count"]       = rng_normal(8, 3, n, 2, 30)
    d["bwd_pkt_count"]       = rng_normal(6, 3, n, 0, 20)
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * rng_normal(300, 50, n, 200, 600)
    d["bwd_bytes_total"]     = d["bwd_pkt_count"] * rng_normal(350, 60, n, 200, 600)
    d["fwd_pkt_len_mean"]    = rng_normal(300, 50, n, 200, 600)
    d["fwd_pkt_len_std"]     = rng_normal(30, 10, n, 0, 100)
    d["fwd_pkt_len_max"]     = np.minimum(600, d["fwd_pkt_len_mean"] + 100)
    d["fwd_pkt_len_min"]     = np.maximum(200, d["fwd_pkt_len_mean"] - 80)
    d["bwd_pkt_len_mean"]    = rng_normal(340, 60, n, 200, 600)
    d["bwd_pkt_len_std"]     = rng_normal(35, 12, n, 0)
    d["bwd_pkt_len_max"]     = np.minimum(600, d["bwd_pkt_len_mean"] + 100)
    d["bwd_pkt_len_min"]     = np.maximum(200, d["bwd_pkt_len_mean"] - 80)
    d["flow_bytes_per_sec"]  = (d["fwd_bytes_total"] + d["bwd_bytes_total"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = (d["fwd_pkt_count"] + d["bwd_pkt_count"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(50000, 20000, n, 1000)
    d["flow_iat_std"]        = rng_normal(20000, 8000, n, 0)
    d["flow_iat_max"]        = d["flow_iat_mean"] + 100000
    d["flow_iat_min"]        = np.maximum(0, d["flow_iat_mean"] - 30000)
    d["fwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["fwd_iat_std"]         = d["flow_iat_std"].copy()
    d["fwd_iat_max"]         = d["flow_iat_max"].copy()
    d["fwd_iat_min"]         = d["flow_iat_min"].copy()
    d["bwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["bwd_iat_std"]         = d["flow_iat_std"].copy()
    d["bwd_iat_max"]         = d["flow_iat_max"].copy()
    d["bwd_iat_min"]         = d["flow_iat_min"].copy()
    for f in ["fwd_psh_flags","bwd_psh_flags","fwd_urg_flags","bwd_urg_flags",
              "fin_flag_count","syn_flag_count","rst_flag_count","psh_flag_count",
              "ack_flag_count","urg_flag_count","cwe_flag_count","ece_flag_count"]:
        d[f] = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 28  # UDP+IP
    d["bwd_header_len"]      = d["bwd_pkt_count"] * 28
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = d["bwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["pkt_len_min"]         = d["fwd_pkt_len_min"].copy()
    d["pkt_len_max"]         = np.maximum(d["fwd_pkt_len_max"], d["bwd_pkt_len_max"])
    d["pkt_len_mean"]        = (d["fwd_pkt_len_mean"] + d["bwd_pkt_len_mean"]) / 2
    d["pkt_len_std"]         = (d["fwd_pkt_len_std"] + d["bwd_pkt_len_std"]) / 2
    d["pkt_len_var"]         = d["pkt_len_std"] ** 2
    d["down_up_ratio"]       = d["bwd_bytes_total"] / (d["fwd_bytes_total"] + 1)
    d["avg_pkt_size"]        = d["pkt_len_mean"].copy()
    d["avg_fwd_segment_size"]= d["fwd_pkt_len_mean"].copy()
    d["avg_bwd_segment_size"]= d["bwd_pkt_len_mean"].copy()
    d["fwd_header_len2"]     = d["fwd_header_len"].copy()
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"].copy()
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"].copy()
    d["subflow_bwd_pkts"]    = d["bwd_pkt_count"].copy()
    d["subflow_bwd_bytes"]   = d["bwd_bytes_total"].copy()
    d["init_fwd_win_bytes"]  = np.zeros(n)
    d["init_bwd_win_bytes"]  = np.zeros(n)
    d["fwd_act_data_pkts"]   = d["fwd_pkt_count"].copy()
    d["fwd_seg_size_min"]    = d["fwd_pkt_len_min"].copy()
    d["active_mean"]         = rng_normal(200000, 80000, n, 0)
    d["active_std"]          = rng_normal(60000, 25000, n, 0)
    d["active_max"]          = d["active_mean"] + 200000
    d["active_min"]          = np.maximum(0, d["active_mean"] - 100000)
    d["idle_mean"]           = rng_normal(300000, 100000, n, 0)
    d["idle_std"]            = rng_normal(80000, 30000, n, 0)
    d["idle_max"]            = d["idle_mean"] + 400000
    d["idle_min"]            = np.maximum(0, d["idle_mean"] - 150000)
    d["unique_src_mac"]      = np.ones(n)
    d["unique_dst_mac"]      = np.ones(n)
    d["arp_reply_ratio"]     = rng_float(0.0, 0.1, n)
    d["bcast_ratio"]         = rng_float(0.7, 1.0, n)   # DHCP broadcasts
    d["dhcp_offer_count"]    = rng_normal(5, 2, n, 1, 20)  # clé discriminante
    d["stp_bpdu_count"]      = np.zeros(n)
    d["http_payload_len"]    = np.zeros(n)
    d["http_entropy"]        = np.zeros(n)
    d["has_sql_keyword"]     = np.zeros(n)
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = np.zeros(n)
    d["session_reuse_ratio"] = np.zeros(n)
    d["label"]               = np.full(n, "DHCP_SPOOFING")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# IP SPOOFING
# ─────────────────────────────────────────────────────────────
def gen_ip_spoofing(n=700):
    d = {}
    d["flow_duration"]       = rng_normal(3000000, 1500000, n, 100000)
    d["protocol"]            = RNG.choice([6, 17, 1], n, p=[0.5, 0.3, 0.2])
    d["fwd_pkt_count"]       = rng_normal(200, 80, n, 20, 2000)
    d["bwd_pkt_count"]       = rng_normal(5, 5, n, 0, 30)  # peu de réponses (IP invalides)
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * rng_normal(400, 200, n, 40)
    d["bwd_bytes_total"]     = d["bwd_pkt_count"] * rng_normal(100, 50, n, 0)
    d["fwd_pkt_len_mean"]    = rng_normal(400, 200, n, 40, 1500)
    d["fwd_pkt_len_std"]     = rng_normal(200, 80, n, 0)
    d["fwd_pkt_len_max"]     = np.minimum(1500, d["fwd_pkt_len_mean"] + 400)
    d["fwd_pkt_len_min"]     = np.maximum(40, d["fwd_pkt_len_mean"] - 200)
    d["bwd_pkt_len_mean"]    = rng_normal(100, 50, n, 0, 200)
    d["bwd_pkt_len_std"]     = rng_normal(30, 15, n, 0)
    d["bwd_pkt_len_max"]     = np.minimum(200, d["bwd_pkt_len_mean"] + 80)
    d["bwd_pkt_len_min"]     = np.maximum(0, d["bwd_pkt_len_mean"] - 50)
    d["flow_bytes_per_sec"]  = (d["fwd_bytes_total"] + d["bwd_bytes_total"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = (d["fwd_pkt_count"] + d["bwd_pkt_count"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(3000, 1500, n, 100, 30000)
    d["flow_iat_std"]        = rng_normal(1500, 700, n, 0)
    d["flow_iat_max"]        = d["flow_iat_mean"] + rng_normal(5000, 2000, n, 0)
    d["flow_iat_min"]        = np.maximum(10, d["flow_iat_mean"] - rng_normal(2000, 800, n, 0))
    d["fwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["fwd_iat_std"]         = d["flow_iat_std"].copy()
    d["fwd_iat_max"]         = d["flow_iat_max"].copy()
    d["fwd_iat_min"]         = d["flow_iat_min"].copy()
    d["bwd_iat_mean"]        = rng_normal(50000, 20000, n, 0)
    d["bwd_iat_std"]         = rng_normal(20000, 8000, n, 0)
    d["bwd_iat_max"]         = d["bwd_iat_mean"] + 100000
    d["bwd_iat_min"]         = np.maximum(0, d["bwd_iat_mean"] - 30000)
    d["fwd_psh_flags"]       = rng_int(0, 5, n)
    d["bwd_psh_flags"]       = np.zeros(n)
    d["fwd_urg_flags"]       = np.zeros(n)
    d["bwd_urg_flags"]       = np.zeros(n)
    d["fin_flag_count"]      = rng_int(0, 2, n)
    d["syn_flag_count"]      = rng_int(1, 10, n)
    d["rst_flag_count"]      = rng_int(0, 3, n)
    d["psh_flag_count"]      = rng_int(0, 5, n)
    d["ack_flag_count"]      = d["bwd_pkt_count"].astype(int)
    d["urg_flag_count"]      = np.zeros(n)
    d["cwe_flag_count"]      = np.zeros(n)
    d["ece_flag_count"]      = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 20
    d["bwd_header_len"]      = d["bwd_pkt_count"] * 20
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = d["bwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["pkt_len_min"]         = d["fwd_pkt_len_min"].copy()
    d["pkt_len_max"]         = np.maximum(d["fwd_pkt_len_max"], d["bwd_pkt_len_max"])
    d["pkt_len_mean"]        = d["fwd_pkt_len_mean"].copy()
    d["pkt_len_std"]         = d["fwd_pkt_len_std"].copy()
    d["pkt_len_var"]         = d["pkt_len_std"] ** 2
    d["down_up_ratio"]       = d["bwd_bytes_total"] / (d["fwd_bytes_total"] + 1)
    d["avg_pkt_size"]        = d["pkt_len_mean"].copy()
    d["avg_fwd_segment_size"]= d["fwd_pkt_len_mean"].copy()
    d["avg_bwd_segment_size"]= d["bwd_pkt_len_mean"].copy()
    d["fwd_header_len2"]     = d["fwd_header_len"].copy()
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"].copy()
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"].copy()
    d["subflow_bwd_pkts"]    = d["bwd_pkt_count"].copy()
    d["subflow_bwd_bytes"]   = d["bwd_bytes_total"].copy()
    d["init_fwd_win_bytes"]  = rng_int(0, 1024, n)
    d["init_bwd_win_bytes"]  = rng_int(0, 1024, n)
    d["fwd_act_data_pkts"]   = d["fwd_pkt_count"].copy()
    d["fwd_seg_size_min"]    = d["fwd_pkt_len_min"].copy()
    d["active_mean"]         = rng_normal(100000, 50000, n, 0)
    d["active_std"]          = rng_normal(40000, 20000, n, 0)
    d["active_max"]          = d["active_mean"] + 150000
    d["active_min"]          = np.maximum(0, d["active_mean"] - 60000)
    d["idle_mean"]           = rng_normal(500000, 200000, n, 0)
    d["idle_std"]            = rng_normal(150000, 70000, n, 0)
    d["idle_max"]            = d["idle_mean"] + 600000
    d["idle_min"]            = np.maximum(0, d["idle_mean"] - 200000)
    d["unique_src_mac"]      = np.ones(n)  # même MAC mais IPs sources très variées
    d["unique_dst_mac"]      = np.ones(n)
    d["arp_reply_ratio"]     = rng_float(0.0, 0.1, n)
    d["bcast_ratio"]         = rng_float(0.0, 0.2, n)
    d["dhcp_offer_count"]    = np.zeros(n)
    d["stp_bpdu_count"]      = np.zeros(n)
    d["http_payload_len"]    = rng_normal(200, 100, n, 0, 1000)
    d["http_entropy"]        = rng_normal(5.5, 1.0, n, 0, 8)  # entropie élevée (IPs aléatoires)
    d["has_sql_keyword"]     = np.zeros(n)
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = rng_int(0, 2, n)
    d["session_reuse_ratio"] = rng_float(0.0, 0.1, n)
    d["label"]               = np.full(n, "IP_SPOOFING")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# SYN FLOOD
# ─────────────────────────────────────────────────────────────
def gen_syn_flood(n=1500):
    d = {}
    d["flow_duration"]       = rng_normal(10000000, 5000000, n, 1000000)
    d["protocol"]            = np.full(n, 6)  # TCP
    d["fwd_pkt_count"]       = rng_normal(8000, 3000, n, 1000, 100000)
    d["bwd_pkt_count"]       = d["fwd_pkt_count"] * rng_float(0.0, 0.05, n)  # presque pas de réponse
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * 60  # SYN = header seulement
    d["bwd_bytes_total"]     = d["bwd_pkt_count"] * 60
    d["fwd_pkt_len_mean"]    = rng_normal(60, 5, n, 40, 80)
    d["fwd_pkt_len_std"]     = rng_normal(3, 1, n, 0, 10)
    d["fwd_pkt_len_max"]     = np.minimum(100, d["fwd_pkt_len_mean"] + 20)
    d["fwd_pkt_len_min"]     = np.maximum(40, d["fwd_pkt_len_mean"] - 15)
    d["bwd_pkt_len_mean"]    = rng_normal(60, 5, n, 0, 80)
    d["bwd_pkt_len_std"]     = rng_normal(3, 1, n, 0)
    d["bwd_pkt_len_max"]     = d["bwd_pkt_len_mean"] + 10
    d["bwd_pkt_len_min"]     = np.maximum(0, d["bwd_pkt_len_mean"] - 10)
    d["flow_bytes_per_sec"]  = d["fwd_bytes_total"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(150, 80, n, 10, 2000)  # très rapide
    d["flow_iat_std"]        = rng_normal(60, 30, n, 0)
    d["flow_iat_max"]        = d["flow_iat_mean"] + rng_normal(500, 200, n, 0)
    d["flow_iat_min"]        = np.maximum(1, d["flow_iat_mean"] - 100)
    d["fwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["fwd_iat_std"]         = d["flow_iat_std"].copy()
    d["fwd_iat_max"]         = d["flow_iat_max"].copy()
    d["fwd_iat_min"]         = d["flow_iat_min"].copy()
    d["bwd_iat_mean"]        = rng_normal(5000, 2000, n, 0)
    d["bwd_iat_std"]         = rng_normal(2000, 1000, n, 0)
    d["bwd_iat_max"]         = d["bwd_iat_mean"] + 10000
    d["bwd_iat_min"]         = np.maximum(0, d["bwd_iat_mean"] - 2000)
    d["fwd_psh_flags"]       = np.zeros(n)
    d["bwd_psh_flags"]       = np.zeros(n)
    d["fwd_urg_flags"]       = np.zeros(n)
    d["bwd_urg_flags"]       = np.zeros(n)
    d["fin_flag_count"]      = np.zeros(n)
    d["syn_flag_count"]      = d["fwd_pkt_count"].astype(int)  # TOUS les paquets ont SYN
    d["rst_flag_count"]      = rng_int(0, 10, n)
    d["psh_flag_count"]      = np.zeros(n)
    d["ack_flag_count"]      = d["bwd_pkt_count"].astype(int)  # ACK seulement côté serveur
    d["urg_flag_count"]      = np.zeros(n)
    d["cwe_flag_count"]      = np.zeros(n)
    d["ece_flag_count"]      = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 20
    d["bwd_header_len"]      = d["bwd_pkt_count"] * 20
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = d["bwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["pkt_len_min"]         = d["fwd_pkt_len_min"].copy()
    d["pkt_len_max"]         = d["fwd_pkt_len_max"].copy()
    d["pkt_len_mean"]        = d["fwd_pkt_len_mean"].copy()
    d["pkt_len_std"]         = d["fwd_pkt_len_std"].copy()
    d["pkt_len_var"]         = d["pkt_len_std"] ** 2
    d["down_up_ratio"]       = d["bwd_bytes_total"] / (d["fwd_bytes_total"] + 1)  # très bas
    d["avg_pkt_size"]        = d["pkt_len_mean"].copy()
    d["avg_fwd_segment_size"]= d["fwd_pkt_len_mean"].copy()
    d["avg_bwd_segment_size"]= d["bwd_pkt_len_mean"].copy()
    d["fwd_header_len2"]     = d["fwd_header_len"].copy()
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"].copy()
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"].copy()
    d["subflow_bwd_pkts"]    = d["bwd_pkt_count"].copy()
    d["subflow_bwd_bytes"]   = d["bwd_bytes_total"].copy()
    d["init_fwd_win_bytes"]  = rng_int(0, 512, n)
    d["init_bwd_win_bytes"]  = rng_int(0, 512, n)
    d["fwd_act_data_pkts"]   = np.zeros(n)  # pas de data, que des SYN
    d["fwd_seg_size_min"]    = d["fwd_pkt_len_min"].copy()
    d["active_mean"]         = rng_normal(50000, 20000, n, 0)
    d["active_std"]          = rng_normal(15000, 6000, n, 0)
    d["active_max"]          = d["active_mean"] + 80000
    d["active_min"]          = np.maximum(0, d["active_mean"] - 30000)
    d["idle_mean"]           = rng_normal(100000, 50000, n, 0)
    d["idle_std"]            = rng_normal(40000, 20000, n, 0)
    d["idle_max"]            = d["idle_mean"] + 200000
    d["idle_min"]            = np.maximum(0, d["idle_mean"] - 60000)
    d["unique_src_mac"]      = rng_int(1, 10, n)
    d["unique_dst_mac"]      = np.ones(n)
    d["arp_reply_ratio"]     = rng_float(0.0, 0.05, n)
    d["bcast_ratio"]         = rng_float(0.0, 0.1, n)
    d["dhcp_offer_count"]    = np.zeros(n)
    d["stp_bpdu_count"]      = np.zeros(n)
    d["http_payload_len"]    = np.zeros(n)
    d["http_entropy"]        = np.zeros(n)
    d["has_sql_keyword"]     = np.zeros(n)
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = np.zeros(n)
    d["session_reuse_ratio"] = np.zeros(n)
    d["label"]               = np.full(n, "SYN_FLOOD")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# DDOS
# ─────────────────────────────────────────────────────────────
def gen_ddos(n=1500):
    d = {}
    d["flow_duration"]       = rng_normal(20000000, 8000000, n, 2000000)
    d["protocol"]            = RNG.choice([6, 17, 1], n, p=[0.4, 0.4, 0.2])
    d["fwd_pkt_count"]       = rng_normal(50000, 20000, n, 5000, 500000)
    d["bwd_pkt_count"]       = d["fwd_pkt_count"] * rng_float(0.0, 0.02, n)
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * rng_normal(500, 300, n, 64, 1500)
    d["bwd_bytes_total"]     = d["bwd_pkt_count"] * 100
    d["fwd_pkt_len_mean"]    = rng_normal(500, 300, n, 64, 1500)
    d["fwd_pkt_len_std"]     = rng_normal(200, 100, n, 0)
    d["fwd_pkt_len_max"]     = np.minimum(1500, d["fwd_pkt_len_mean"] + 500)
    d["fwd_pkt_len_min"]     = np.maximum(64, d["fwd_pkt_len_mean"] - 200)
    d["bwd_pkt_len_mean"]    = rng_normal(100, 50, n, 0, 200)
    d["bwd_pkt_len_std"]     = rng_normal(30, 15, n, 0)
    d["bwd_pkt_len_max"]     = d["bwd_pkt_len_mean"] + 100
    d["bwd_pkt_len_min"]     = np.maximum(0, d["bwd_pkt_len_mean"] - 50)
    d["flow_bytes_per_sec"]  = d["fwd_bytes_total"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(50, 30, n, 1, 500)  # ultra rapide
    d["flow_iat_std"]        = rng_normal(20, 10, n, 0)
    d["flow_iat_max"]        = d["flow_iat_mean"] + 200
    d["flow_iat_min"]        = np.maximum(1, d["flow_iat_mean"] - 30)
    d["fwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["fwd_iat_std"]         = d["flow_iat_std"].copy()
    d["fwd_iat_max"]         = d["flow_iat_max"].copy()
    d["fwd_iat_min"]         = d["flow_iat_min"].copy()
    d["bwd_iat_mean"]        = rng_normal(1000, 500, n, 0)
    d["bwd_iat_std"]         = rng_normal(300, 150, n, 0)
    d["bwd_iat_max"]         = d["bwd_iat_mean"] + 3000
    d["bwd_iat_min"]         = np.maximum(0, d["bwd_iat_mean"] - 500)
    d["fwd_psh_flags"]       = rng_int(0, 3, n)
    d["bwd_psh_flags"]       = np.zeros(n)
    d["fwd_urg_flags"]       = np.zeros(n)
    d["bwd_urg_flags"]       = np.zeros(n)
    d["fin_flag_count"]      = rng_int(0, 2, n)
    d["syn_flag_count"]      = rng_int(0, 5, n)
    d["rst_flag_count"]      = rng_int(0, 3, n)
    d["psh_flag_count"]      = rng_int(0, 5, n)
    d["ack_flag_count"]      = d["bwd_pkt_count"].astype(int)
    d["urg_flag_count"]      = np.zeros(n)
    d["cwe_flag_count"]      = np.zeros(n)
    d["ece_flag_count"]      = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 20
    d["bwd_header_len"]      = d["bwd_pkt_count"] * 20
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = d["bwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["pkt_len_min"]         = d["fwd_pkt_len_min"].copy()
    d["pkt_len_max"]         = d["fwd_pkt_len_max"].copy()
    d["pkt_len_mean"]        = d["fwd_pkt_len_mean"].copy()
    d["pkt_len_std"]         = d["fwd_pkt_len_std"].copy()
    d["pkt_len_var"]         = d["pkt_len_std"] ** 2
    d["down_up_ratio"]       = d["bwd_bytes_total"] / (d["fwd_bytes_total"] + 1)
    d["avg_pkt_size"]        = d["pkt_len_mean"].copy()
    d["avg_fwd_segment_size"]= d["fwd_pkt_len_mean"].copy()
    d["avg_bwd_segment_size"]= d["bwd_pkt_len_mean"].copy()
    d["fwd_header_len2"]     = d["fwd_header_len"].copy()
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"].copy()
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"].copy()
    d["subflow_bwd_pkts"]    = d["bwd_pkt_count"].copy()
    d["subflow_bwd_bytes"]   = d["bwd_bytes_total"].copy()
    d["init_fwd_win_bytes"]  = rng_int(0, 1024, n)
    d["init_bwd_win_bytes"]  = rng_int(0, 512, n)
    d["fwd_act_data_pkts"]   = d["fwd_pkt_count"].copy()
    d["fwd_seg_size_min"]    = d["fwd_pkt_len_min"].copy()
    d["active_mean"]         = rng_normal(30000, 15000, n, 0)
    d["active_std"]          = rng_normal(10000, 5000, n, 0)
    d["active_max"]          = d["active_mean"] + 50000
    d["active_min"]          = np.maximum(0, d["active_mean"] - 15000)
    d["idle_mean"]           = rng_normal(50000, 25000, n, 0)
    d["idle_std"]            = rng_normal(15000, 7000, n, 0)
    d["idle_max"]            = d["idle_mean"] + 100000
    d["idle_min"]            = np.maximum(0, d["idle_mean"] - 20000)
    d["unique_src_mac"]      = rng_normal(500, 200, n, 50, 5000)  # beaucoup de sources
    d["unique_dst_mac"]      = np.ones(n)
    d["arp_reply_ratio"]     = rng_float(0.0, 0.05, n)
    d["bcast_ratio"]         = rng_float(0.0, 0.1, n)
    d["dhcp_offer_count"]    = np.zeros(n)
    d["stp_bpdu_count"]      = np.zeros(n)
    d["http_payload_len"]    = rng_normal(300, 200, n, 0, 2000)
    d["http_entropy"]        = rng_normal(6.0, 1.0, n, 0, 8)
    d["has_sql_keyword"]     = np.zeros(n)
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = rng_int(0, 2, n)
    d["session_reuse_ratio"] = rng_float(0.0, 0.05, n)
    d["label"]               = np.full(n, "DDOS")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# PORT SCAN
# ─────────────────────────────────────────────────────────────
def gen_port_scan(n=1000):
    d = {}
    d["flow_duration"]       = rng_normal(100000, 50000, n, 1000, 1000000)
    d["protocol"]            = np.full(n, 6)
    d["fwd_pkt_count"]       = rng_int(1, 3, n)  # 1-2 paquets par connexion
    d["bwd_pkt_count"]       = rng_int(0, 2, n)
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * 60
    d["bwd_bytes_total"]     = d["bwd_pkt_count"] * 44
    d["fwd_pkt_len_mean"]    = rng_normal(60, 5, n, 40, 80)
    d["fwd_pkt_len_std"]     = np.zeros(n)
    d["fwd_pkt_len_max"]     = d["fwd_pkt_len_mean"] + 5
    d["fwd_pkt_len_min"]     = d["fwd_pkt_len_mean"] - 5
    d["bwd_pkt_len_mean"]    = rng_normal(44, 3, n, 0, 60)
    d["bwd_pkt_len_std"]     = np.zeros(n)
    d["bwd_pkt_len_max"]     = d["bwd_pkt_len_mean"] + 5
    d["bwd_pkt_len_min"]     = np.maximum(0, d["bwd_pkt_len_mean"] - 5)
    d["flow_bytes_per_sec"]  = (d["fwd_bytes_total"] + d["bwd_bytes_total"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = (d["fwd_pkt_count"] + d["bwd_pkt_count"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(5000, 2000, n, 100, 50000)
    d["flow_iat_std"]        = rng_normal(1000, 500, n, 0)
    d["flow_iat_max"]        = d["flow_iat_mean"] + 10000
    d["flow_iat_min"]        = np.maximum(0, d["flow_iat_mean"] - 3000)
    d["fwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["fwd_iat_std"]         = d["flow_iat_std"].copy()
    d["fwd_iat_max"]         = d["flow_iat_max"].copy()
    d["fwd_iat_min"]         = d["flow_iat_min"].copy()
    d["bwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["bwd_iat_std"]         = d["flow_iat_std"].copy()
    d["bwd_iat_max"]         = d["flow_iat_max"].copy()
    d["bwd_iat_min"]         = d["flow_iat_min"].copy()
    d["fwd_psh_flags"]       = np.zeros(n)
    d["bwd_psh_flags"]       = np.zeros(n)
    d["fwd_urg_flags"]       = np.zeros(n)
    d["bwd_urg_flags"]       = np.zeros(n)
    d["fin_flag_count"]      = rng_int(0, 1, n)
    d["syn_flag_count"]      = np.ones(n)  # toujours SYN (SYN scan)
    d["rst_flag_count"]      = rng_int(0, 1, n)
    d["psh_flag_count"]      = np.zeros(n)
    d["ack_flag_count"]      = rng_int(0, 1, n)
    d["urg_flag_count"]      = np.zeros(n)
    d["cwe_flag_count"]      = np.zeros(n)
    d["ece_flag_count"]      = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 20
    d["bwd_header_len"]      = d["bwd_pkt_count"] * 20
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = d["bwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["pkt_len_min"]         = d["fwd_pkt_len_min"].copy()
    d["pkt_len_max"]         = d["fwd_pkt_len_max"].copy()
    d["pkt_len_mean"]        = d["fwd_pkt_len_mean"].copy()
    d["pkt_len_std"]         = d["fwd_pkt_len_std"].copy()
    d["pkt_len_var"]         = d["pkt_len_std"] ** 2
    d["down_up_ratio"]       = d["bwd_bytes_total"] / (d["fwd_bytes_total"] + 1)
    d["avg_pkt_size"]        = d["pkt_len_mean"].copy()
    d["avg_fwd_segment_size"]= d["fwd_pkt_len_mean"].copy()
    d["avg_bwd_segment_size"]= d["bwd_pkt_len_mean"].copy()
    d["fwd_header_len2"]     = d["fwd_header_len"].copy()
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"].copy()
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"].copy()
    d["subflow_bwd_pkts"]    = d["bwd_pkt_count"].copy()
    d["subflow_bwd_bytes"]   = d["bwd_bytes_total"].copy()
    d["init_fwd_win_bytes"]  = rng_int(0, 512, n)
    d["init_bwd_win_bytes"]  = rng_int(0, 512, n)
    d["fwd_act_data_pkts"]   = np.zeros(n)
    d["fwd_seg_size_min"]    = d["fwd_pkt_len_min"].copy()
    d["active_mean"]         = rng_normal(10000, 5000, n, 0)
    d["active_std"]          = rng_normal(3000, 1500, n, 0)
    d["active_max"]          = d["active_mean"] + 20000
    d["active_min"]          = np.maximum(0, d["active_mean"] - 5000)
    d["idle_mean"]           = rng_normal(50000, 25000, n, 0)
    d["idle_std"]            = rng_normal(15000, 7000, n, 0)
    d["idle_max"]            = d["idle_mean"] + 100000
    d["idle_min"]            = np.maximum(0, d["idle_mean"] - 20000)
    d["unique_src_mac"]      = np.ones(n)
    d["unique_dst_mac"]      = np.ones(n)
    d["arp_reply_ratio"]     = rng_float(0.0, 0.05, n)
    d["bcast_ratio"]         = rng_float(0.0, 0.05, n)
    d["dhcp_offer_count"]    = np.zeros(n)
    d["stp_bpdu_count"]      = np.zeros(n)
    d["http_payload_len"]    = np.zeros(n)
    d["http_entropy"]        = np.zeros(n)
    d["has_sql_keyword"]     = np.zeros(n)
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = np.zeros(n)
    d["session_reuse_ratio"] = np.zeros(n)
    d["label"]               = np.full(n, "PORT_SCAN")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# ROUTING ATTACK (BGP/OSPF Poisoning)
# ─────────────────────────────────────────────────────────────
def gen_routing_attack(n=400):
    d = {}
    d["flow_duration"]       = rng_normal(60000000, 30000000, n, 5000000)
    d["protocol"]            = RNG.choice([6, 89], n, p=[0.5, 0.5])  # TCP (BGP) / OSPF=89
    d["fwd_pkt_count"]       = rng_normal(100, 40, n, 20, 500)
    d["bwd_pkt_count"]       = rng_normal(80, 35, n, 10, 400)
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * rng_normal(200, 80, n, 60, 1000)
    d["bwd_bytes_total"]     = d["bwd_pkt_count"] * rng_normal(180, 70, n, 60, 1000)
    d["fwd_pkt_len_mean"]    = rng_normal(200, 80, n, 60, 1000)
    d["fwd_pkt_len_std"]     = rng_normal(60, 25, n, 0)
    d["fwd_pkt_len_max"]     = np.minimum(1000, d["fwd_pkt_len_mean"] + 200)
    d["fwd_pkt_len_min"]     = np.maximum(60, d["fwd_pkt_len_mean"] - 100)
    d["bwd_pkt_len_mean"]    = rng_normal(180, 70, n, 60, 900)
    d["bwd_pkt_len_std"]     = rng_normal(55, 22, n, 0)
    d["bwd_pkt_len_max"]     = np.minimum(900, d["bwd_pkt_len_mean"] + 180)
    d["bwd_pkt_len_min"]     = np.maximum(60, d["bwd_pkt_len_mean"] - 90)
    d["flow_bytes_per_sec"]  = (d["fwd_bytes_total"] + d["bwd_bytes_total"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = (d["fwd_pkt_count"] + d["bwd_pkt_count"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(500000, 200000, n, 10000)  # updates périodiques
    d["flow_iat_std"]        = rng_normal(100000, 50000, n, 0)
    d["flow_iat_max"]        = d["flow_iat_mean"] + 1000000
    d["flow_iat_min"]        = np.maximum(0, d["flow_iat_mean"] - 300000)
    d["fwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["fwd_iat_std"]         = d["flow_iat_std"].copy()
    d["fwd_iat_max"]         = d["flow_iat_max"].copy()
    d["fwd_iat_min"]         = d["flow_iat_min"].copy()
    d["bwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["bwd_iat_std"]         = d["flow_iat_std"].copy()
    d["bwd_iat_max"]         = d["flow_iat_max"].copy()
    d["bwd_iat_min"]         = d["flow_iat_min"].copy()
    d["fwd_psh_flags"]       = rng_int(0, 5, n)
    d["bwd_psh_flags"]       = rng_int(0, 5, n)
    d["fwd_urg_flags"]       = np.zeros(n)
    d["bwd_urg_flags"]       = np.zeros(n)
    d["fin_flag_count"]      = rng_int(0, 2, n)
    d["syn_flag_count"]      = rng_int(1, 3, n)
    d["rst_flag_count"]      = rng_int(0, 2, n)
    d["psh_flag_count"]      = rng_int(2, 10, n)
    d["ack_flag_count"]      = d["bwd_pkt_count"].astype(int)
    d["urg_flag_count"]      = np.zeros(n)
    d["cwe_flag_count"]      = np.zeros(n)
    d["ece_flag_count"]      = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 20
    d["bwd_header_len"]      = d["bwd_pkt_count"] * 20
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = d["bwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["pkt_len_min"]         = d["fwd_pkt_len_min"].copy()
    d["pkt_len_max"]         = np.maximum(d["fwd_pkt_len_max"], d["bwd_pkt_len_max"])
    d["pkt_len_mean"]        = (d["fwd_pkt_len_mean"] + d["bwd_pkt_len_mean"]) / 2
    d["pkt_len_std"]         = (d["fwd_pkt_len_std"] + d["bwd_pkt_len_std"]) / 2
    d["pkt_len_var"]         = d["pkt_len_std"] ** 2
    d["down_up_ratio"]       = d["bwd_bytes_total"] / (d["fwd_bytes_total"] + 1)
    d["avg_pkt_size"]        = d["pkt_len_mean"].copy()
    d["avg_fwd_segment_size"]= d["fwd_pkt_len_mean"].copy()
    d["avg_bwd_segment_size"]= d["bwd_pkt_len_mean"].copy()
    d["fwd_header_len2"]     = d["fwd_header_len"].copy()
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"].copy()
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"].copy()
    d["subflow_bwd_pkts"]    = d["bwd_pkt_count"].copy()
    d["subflow_bwd_bytes"]   = d["bwd_bytes_total"].copy()
    d["init_fwd_win_bytes"]  = rng_int(8192, 32768, n)
    d["init_bwd_win_bytes"]  = rng_int(8192, 32768, n)
    d["fwd_act_data_pkts"]   = d["fwd_pkt_count"].copy()
    d["fwd_seg_size_min"]    = d["fwd_pkt_len_min"].copy()
    d["active_mean"]         = rng_normal(500000, 200000, n, 0)
    d["active_std"]          = rng_normal(150000, 70000, n, 0)
    d["active_max"]          = d["active_mean"] + 1000000
    d["active_min"]          = np.maximum(0, d["active_mean"] - 300000)
    d["idle_mean"]           = rng_normal(10000000, 5000000, n, 0)
    d["idle_std"]            = rng_normal(3000000, 1500000, n, 0)
    d["idle_max"]            = d["idle_mean"] + 20000000
    d["idle_min"]            = np.maximum(0, d["idle_mean"] - 5000000)
    d["unique_src_mac"]      = np.ones(n)
    d["unique_dst_mac"]      = rng_int(1, 5, n)
    d["arp_reply_ratio"]     = rng_float(0.0, 0.1, n)
    d["bcast_ratio"]         = rng_float(0.3, 0.7, n)  # multicast OSPF
    d["dhcp_offer_count"]    = np.zeros(n)
    d["stp_bpdu_count"]      = np.zeros(n)
    d["http_payload_len"]    = np.zeros(n)
    d["http_entropy"]        = np.zeros(n)
    d["has_sql_keyword"]     = np.zeros(n)
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = np.zeros(n)
    d["session_reuse_ratio"] = np.zeros(n)
    d["label"]               = np.full(n, "ROUTING_ATTACK")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# SQL INJECTION
# ─────────────────────────────────────────────────────────────
def gen_sql_injection(n=700):
    d = {}
    d["flow_duration"]       = rng_normal(200000, 100000, n, 10000, 2000000)
    d["protocol"]            = np.full(n, 6)
    d["fwd_pkt_count"]       = rng_normal(6, 3, n, 2, 30)
    d["bwd_pkt_count"]       = rng_normal(8, 4, n, 1, 40)
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * rng_normal(800, 400, n, 100, 4000)
    d["bwd_bytes_total"]     = d["bwd_pkt_count"] * rng_normal(600, 300, n, 100, 3000)
    d["fwd_pkt_len_mean"]    = rng_normal(800, 400, n, 100, 4000)
    d["fwd_pkt_len_std"]     = rng_normal(300, 150, n, 0)
    d["fwd_pkt_len_max"]     = np.minimum(4000, d["fwd_pkt_len_mean"] + 1000)
    d["fwd_pkt_len_min"]     = np.maximum(100, d["fwd_pkt_len_mean"] - 400)
    d["bwd_pkt_len_mean"]    = rng_normal(600, 300, n, 100, 3000)
    d["bwd_pkt_len_std"]     = rng_normal(200, 100, n, 0)
    d["bwd_pkt_len_max"]     = np.minimum(3000, d["bwd_pkt_len_mean"] + 800)
    d["bwd_pkt_len_min"]     = np.maximum(100, d["bwd_pkt_len_mean"] - 300)
    d["flow_bytes_per_sec"]  = (d["fwd_bytes_total"] + d["bwd_bytes_total"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = (d["fwd_pkt_count"] + d["bwd_pkt_count"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(20000, 10000, n, 1000)
    d["flow_iat_std"]        = rng_normal(8000, 4000, n, 0)
    d["flow_iat_max"]        = d["flow_iat_mean"] + 50000
    d["flow_iat_min"]        = np.maximum(0, d["flow_iat_mean"] - 10000)
    d["fwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["fwd_iat_std"]         = d["flow_iat_std"].copy()
    d["fwd_iat_max"]         = d["flow_iat_max"].copy()
    d["fwd_iat_min"]         = d["flow_iat_min"].copy()
    d["bwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["bwd_iat_std"]         = d["flow_iat_std"].copy()
    d["bwd_iat_max"]         = d["flow_iat_max"].copy()
    d["bwd_iat_min"]         = d["flow_iat_min"].copy()
    d["fwd_psh_flags"]       = rng_int(1, 4, n)
    d["bwd_psh_flags"]       = rng_int(1, 4, n)
    d["fwd_urg_flags"]       = np.zeros(n)
    d["bwd_urg_flags"]       = np.zeros(n)
    d["fin_flag_count"]      = rng_int(0, 2, n)
    d["syn_flag_count"]      = np.ones(n)
    d["rst_flag_count"]      = np.zeros(n)
    d["psh_flag_count"]      = rng_int(2, 8, n)
    d["ack_flag_count"]      = d["bwd_pkt_count"].astype(int)
    d["urg_flag_count"]      = np.zeros(n)
    d["cwe_flag_count"]      = np.zeros(n)
    d["ece_flag_count"]      = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 20
    d["bwd_header_len"]      = d["bwd_pkt_count"] * 20
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = d["bwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["pkt_len_min"]         = d["fwd_pkt_len_min"].copy()
    d["pkt_len_max"]         = np.maximum(d["fwd_pkt_len_max"], d["bwd_pkt_len_max"])
    d["pkt_len_mean"]        = (d["fwd_pkt_len_mean"] + d["bwd_pkt_len_mean"]) / 2
    d["pkt_len_std"]         = (d["fwd_pkt_len_std"] + d["bwd_pkt_len_std"]) / 2
    d["pkt_len_var"]         = d["pkt_len_std"] ** 2
    d["down_up_ratio"]       = d["bwd_bytes_total"] / (d["fwd_bytes_total"] + 1)
    d["avg_pkt_size"]        = d["pkt_len_mean"].copy()
    d["avg_fwd_segment_size"]= d["fwd_pkt_len_mean"].copy()
    d["avg_bwd_segment_size"]= d["bwd_pkt_len_mean"].copy()
    d["fwd_header_len2"]     = d["fwd_header_len"].copy()
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"].copy()
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"].copy()
    d["subflow_bwd_pkts"]    = d["bwd_pkt_count"].copy()
    d["subflow_bwd_bytes"]   = d["bwd_bytes_total"].copy()
    d["init_fwd_win_bytes"]  = rng_int(8192, 65536, n)
    d["init_bwd_win_bytes"]  = rng_int(8192, 65536, n)
    d["fwd_act_data_pkts"]   = d["fwd_pkt_count"].copy()
    d["fwd_seg_size_min"]    = d["fwd_pkt_len_min"].copy()
    d["active_mean"]         = rng_normal(100000, 50000, n, 0)
    d["active_std"]          = rng_normal(30000, 15000, n, 0)
    d["active_max"]          = d["active_mean"] + 200000
    d["active_min"]          = np.maximum(0, d["active_mean"] - 60000)
    d["idle_mean"]           = rng_normal(500000, 200000, n, 0)
    d["idle_std"]            = rng_normal(150000, 70000, n, 0)
    d["idle_max"]            = d["idle_mean"] + 1000000
    d["idle_min"]            = np.maximum(0, d["idle_mean"] - 200000)
    d["unique_src_mac"]      = np.ones(n)
    d["unique_dst_mac"]      = np.ones(n)
    d["arp_reply_ratio"]     = rng_float(0.0, 0.05, n)
    d["bcast_ratio"]         = rng_float(0.0, 0.05, n)
    d["dhcp_offer_count"]    = np.zeros(n)
    d["stp_bpdu_count"]      = np.zeros(n)
    d["http_payload_len"]    = rng_normal(2000, 800, n, 200, 8000)   # payload HTTP élevé
    d["http_entropy"]        = rng_normal(6.5, 0.8, n, 4, 8)         # entropie haute (SQL chars)
    d["has_sql_keyword"]     = np.ones(n)                            # clé discriminante
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = RNG.choice([0, 12, 13], n, p=[0.3, 0.3, 0.4])
    d["session_reuse_ratio"] = rng_float(0.0, 0.3, n)
    d["label"]               = np.full(n, "SQL_INJECTION")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# XSS
# ─────────────────────────────────────────────────────────────
def gen_xss(n=700):
    d = {}
    # Similaire SQL injection mais payload différent
    base = gen_sql_injection(n)
    base["http_payload_len"]  = rng_normal(1500, 600, n, 100, 6000)
    base["http_entropy"]      = rng_normal(6.0, 0.9, n, 3, 8)
    base["has_sql_keyword"]   = np.zeros(n)
    base["has_script_tag"]    = np.ones(n)   # clé discriminante
    base["label"]             = np.full(n, "XSS")
    return base


# ─────────────────────────────────────────────────────────────
# SSL/TLS STRIPPING
# ─────────────────────────────────────────────────────────────
def gen_ssl_stripping(n=500):
    d = {}
    d["flow_duration"]       = rng_normal(2000000, 1000000, n, 100000)
    d["protocol"]            = np.full(n, 6)
    d["fwd_pkt_count"]       = rng_normal(30, 15, n, 5, 200)
    d["bwd_pkt_count"]       = rng_normal(25, 12, n, 3, 150)
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * rng_normal(600, 200, n, 100)
    d["bwd_bytes_total"]     = d["bwd_pkt_count"] * rng_normal(800, 300, n, 100)
    d["fwd_pkt_len_mean"]    = rng_normal(600, 200, n, 100, 2000)
    d["fwd_pkt_len_std"]     = rng_normal(200, 80, n, 0)
    d["fwd_pkt_len_max"]     = np.minimum(2000, d["fwd_pkt_len_mean"] + 500)
    d["fwd_pkt_len_min"]     = np.maximum(100, d["fwd_pkt_len_mean"] - 300)
    d["bwd_pkt_len_mean"]    = rng_normal(800, 300, n, 100, 2500)
    d["bwd_pkt_len_std"]     = rng_normal(250, 100, n, 0)
    d["bwd_pkt_len_max"]     = np.minimum(2500, d["bwd_pkt_len_mean"] + 600)
    d["bwd_pkt_len_min"]     = np.maximum(100, d["bwd_pkt_len_mean"] - 400)
    d["flow_bytes_per_sec"]  = (d["fwd_bytes_total"] + d["bwd_bytes_total"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = (d["fwd_pkt_count"] + d["bwd_pkt_count"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(40000, 20000, n, 1000)
    d["flow_iat_std"]        = rng_normal(15000, 7000, n, 0)
    d["flow_iat_max"]        = d["flow_iat_mean"] + 100000
    d["flow_iat_min"]        = np.maximum(0, d["flow_iat_mean"] - 20000)
    d["fwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["fwd_iat_std"]         = d["flow_iat_std"].copy()
    d["fwd_iat_max"]         = d["flow_iat_max"].copy()
    d["fwd_iat_min"]         = d["flow_iat_min"].copy()
    d["bwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["bwd_iat_std"]         = d["flow_iat_std"].copy()
    d["bwd_iat_max"]         = d["flow_iat_max"].copy()
    d["bwd_iat_min"]         = d["flow_iat_min"].copy()
    d["fwd_psh_flags"]       = rng_int(1, 5, n)
    d["bwd_psh_flags"]       = rng_int(1, 5, n)
    d["fwd_urg_flags"]       = np.zeros(n)
    d["bwd_urg_flags"]       = np.zeros(n)
    d["fin_flag_count"]      = rng_int(0, 2, n)
    d["syn_flag_count"]      = np.ones(n)
    d["rst_flag_count"]      = np.zeros(n)
    d["psh_flag_count"]      = rng_int(2, 8, n)
    d["ack_flag_count"]      = d["bwd_pkt_count"].astype(int)
    d["urg_flag_count"]      = np.zeros(n)
    d["cwe_flag_count"]      = np.zeros(n)
    d["ece_flag_count"]      = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 20
    d["bwd_header_len"]      = d["bwd_pkt_count"] * 20
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = d["bwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["pkt_len_min"]         = d["fwd_pkt_len_min"].copy()
    d["pkt_len_max"]         = np.maximum(d["fwd_pkt_len_max"], d["bwd_pkt_len_max"])
    d["pkt_len_mean"]        = (d["fwd_pkt_len_mean"] + d["bwd_pkt_len_mean"]) / 2
    d["pkt_len_std"]         = (d["fwd_pkt_len_std"] + d["bwd_pkt_len_std"]) / 2
    d["pkt_len_var"]         = d["pkt_len_std"] ** 2
    d["down_up_ratio"]       = d["bwd_bytes_total"] / (d["fwd_bytes_total"] + 1)
    d["avg_pkt_size"]        = d["pkt_len_mean"].copy()
    d["avg_fwd_segment_size"]= d["fwd_pkt_len_mean"].copy()
    d["avg_bwd_segment_size"]= d["bwd_pkt_len_mean"].copy()
    d["fwd_header_len2"]     = d["fwd_header_len"].copy()
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"].copy()
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"].copy()
    d["subflow_bwd_pkts"]    = d["bwd_pkt_count"].copy()
    d["subflow_bwd_bytes"]   = d["bwd_bytes_total"].copy()
    d["init_fwd_win_bytes"]  = rng_int(8192, 65536, n)
    d["init_bwd_win_bytes"]  = rng_int(8192, 65536, n)
    d["fwd_act_data_pkts"]   = d["fwd_pkt_count"].copy()
    d["fwd_seg_size_min"]    = d["fwd_pkt_len_min"].copy()
    d["active_mean"]         = rng_normal(200000, 80000, n, 0)
    d["active_std"]          = rng_normal(60000, 25000, n, 0)
    d["active_max"]          = d["active_mean"] + 400000
    d["active_min"]          = np.maximum(0, d["active_mean"] - 100000)
    d["idle_mean"]           = rng_normal(800000, 300000, n, 0)
    d["idle_std"]            = rng_normal(200000, 90000, n, 0)
    d["idle_max"]            = d["idle_mean"] + 1500000
    d["idle_min"]            = np.maximum(0, d["idle_mean"] - 300000)
    d["unique_src_mac"]      = np.ones(n)
    d["unique_dst_mac"]      = np.ones(n)
    d["arp_reply_ratio"]     = rng_float(0.0, 0.05, n)
    d["bcast_ratio"]         = rng_float(0.0, 0.05, n)
    d["dhcp_offer_count"]    = np.zeros(n)
    d["stp_bpdu_count"]      = np.zeros(n)
    d["http_payload_len"]    = rng_normal(1000, 400, n, 100, 4000)
    d["http_entropy"]        = rng_normal(4.0, 0.8, n, 2, 7)
    d["has_sql_keyword"]     = np.zeros(n)
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = np.zeros(n)   # CLÉE : connexion non chiffrée (HTTP)
    d["session_reuse_ratio"] = rng_float(0.3, 0.9, n)  # réutilisation session élevée
    d["label"]               = np.full(n, "SSL_STRIPPING")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# SESSION HIJACKING
# ─────────────────────────────────────────────────────────────
def gen_session_hijacking(n=600):
    d = {}
    d["flow_duration"]       = rng_normal(5000000, 2000000, n, 500000)
    d["protocol"]            = np.full(n, 6)
    d["fwd_pkt_count"]       = rng_normal(40, 20, n, 5, 200)
    d["bwd_pkt_count"]       = rng_normal(35, 18, n, 3, 180)
    d["fwd_bytes_total"]     = d["fwd_pkt_count"] * rng_normal(700, 300, n, 100)
    d["bwd_bytes_total"]     = d["bwd_pkt_count"] * rng_normal(900, 400, n, 100)
    d["fwd_pkt_len_mean"]    = rng_normal(700, 300, n, 100, 2000)
    d["fwd_pkt_len_std"]     = rng_normal(200, 80, n, 0)
    d["fwd_pkt_len_max"]     = np.minimum(2000, d["fwd_pkt_len_mean"] + 500)
    d["fwd_pkt_len_min"]     = np.maximum(100, d["fwd_pkt_len_mean"] - 300)
    d["bwd_pkt_len_mean"]    = rng_normal(900, 400, n, 100, 2500)
    d["bwd_pkt_len_std"]     = rng_normal(250, 100, n, 0)
    d["bwd_pkt_len_max"]     = np.minimum(2500, d["bwd_pkt_len_mean"] + 600)
    d["bwd_pkt_len_min"]     = np.maximum(100, d["bwd_pkt_len_mean"] - 400)
    d["flow_bytes_per_sec"]  = (d["fwd_bytes_total"] + d["bwd_bytes_total"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_pkts_per_sec"]   = (d["fwd_pkt_count"] + d["bwd_pkt_count"]) / (d["flow_duration"] / 1e6 + 1e-9)
    d["flow_iat_mean"]       = rng_normal(60000, 25000, n, 1000)
    d["flow_iat_std"]        = rng_normal(20000, 8000, n, 0)
    d["flow_iat_max"]        = d["flow_iat_mean"] + 150000
    d["flow_iat_min"]        = np.maximum(0, d["flow_iat_mean"] - 30000)
    d["fwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["fwd_iat_std"]         = d["flow_iat_std"].copy()
    d["fwd_iat_max"]         = d["flow_iat_max"].copy()
    d["fwd_iat_min"]         = d["flow_iat_min"].copy()
    d["bwd_iat_mean"]        = d["flow_iat_mean"].copy()
    d["bwd_iat_std"]         = d["flow_iat_std"].copy()
    d["bwd_iat_max"]         = d["flow_iat_max"].copy()
    d["bwd_iat_min"]         = d["flow_iat_min"].copy()
    d["fwd_psh_flags"]       = rng_int(1, 5, n)
    d["bwd_psh_flags"]       = rng_int(1, 5, n)
    d["fwd_urg_flags"]       = np.zeros(n)
    d["bwd_urg_flags"]       = np.zeros(n)
    d["fin_flag_count"]      = rng_int(0, 2, n)
    d["syn_flag_count"]      = np.zeros(n)   # pas de nouveau SYN (session existante)
    d["rst_flag_count"]      = np.zeros(n)
    d["psh_flag_count"]      = rng_int(3, 10, n)
    d["ack_flag_count"]      = (d["fwd_pkt_count"] + d["bwd_pkt_count"]).astype(int)
    d["urg_flag_count"]      = np.zeros(n)
    d["cwe_flag_count"]      = np.zeros(n)
    d["ece_flag_count"]      = np.zeros(n)
    d["fwd_header_len"]      = d["fwd_pkt_count"] * 20
    d["bwd_header_len"]      = d["bwd_pkt_count"] * 20
    d["fwd_pkts_per_sec"]    = d["fwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["bwd_pkts_per_sec"]    = d["bwd_pkt_count"] / (d["flow_duration"] / 1e6 + 1e-9)
    d["pkt_len_min"]         = d["fwd_pkt_len_min"].copy()
    d["pkt_len_max"]         = np.maximum(d["fwd_pkt_len_max"], d["bwd_pkt_len_max"])
    d["pkt_len_mean"]        = (d["fwd_pkt_len_mean"] + d["bwd_pkt_len_mean"]) / 2
    d["pkt_len_std"]         = (d["fwd_pkt_len_std"] + d["bwd_pkt_len_std"]) / 2
    d["pkt_len_var"]         = d["pkt_len_std"] ** 2
    d["down_up_ratio"]       = d["bwd_bytes_total"] / (d["fwd_bytes_total"] + 1)
    d["avg_pkt_size"]        = d["pkt_len_mean"].copy()
    d["avg_fwd_segment_size"]= d["fwd_pkt_len_mean"].copy()
    d["avg_bwd_segment_size"]= d["bwd_pkt_len_mean"].copy()
    d["fwd_header_len2"]     = d["fwd_header_len"].copy()
    d["subflow_fwd_pkts"]    = d["fwd_pkt_count"].copy()
    d["subflow_fwd_bytes"]   = d["fwd_bytes_total"].copy()
    d["subflow_bwd_pkts"]    = d["bwd_pkt_count"].copy()
    d["subflow_bwd_bytes"]   = d["bwd_bytes_total"].copy()
    d["init_fwd_win_bytes"]  = rng_int(8192, 65536, n)
    d["init_bwd_win_bytes"]  = rng_int(8192, 65536, n)
    d["fwd_act_data_pkts"]   = d["fwd_pkt_count"].copy()
    d["fwd_seg_size_min"]    = d["fwd_pkt_len_min"].copy()
    d["active_mean"]         = rng_normal(300000, 120000, n, 0)
    d["active_std"]          = rng_normal(80000, 35000, n, 0)
    d["active_max"]          = d["active_mean"] + 600000
    d["active_min"]          = np.maximum(0, d["active_mean"] - 150000)
    d["idle_mean"]           = rng_normal(1000000, 400000, n, 0)
    d["idle_std"]            = rng_normal(300000, 120000, n, 0)
    d["idle_max"]            = d["idle_mean"] + 2000000
    d["idle_min"]            = np.maximum(0, d["idle_mean"] - 400000)
    d["unique_src_mac"]      = np.ones(n)
    d["unique_dst_mac"]      = np.ones(n)
    d["arp_reply_ratio"]     = rng_float(0.0, 0.05, n)
    d["bcast_ratio"]         = rng_float(0.0, 0.05, n)
    d["dhcp_offer_count"]    = np.zeros(n)
    d["stp_bpdu_count"]      = np.zeros(n)
    d["http_payload_len"]    = rng_normal(1500, 600, n, 200, 5000)
    d["http_entropy"]        = rng_normal(4.8, 0.7, n, 3, 7)
    d["has_sql_keyword"]     = np.zeros(n)
    d["has_script_tag"]      = np.zeros(n)
    d["ssl_version_num"]     = RNG.choice([0, 12], n, p=[0.6, 0.4])  # souvent non chiffré
    d["session_reuse_ratio"] = rng_float(0.7, 1.0, n)  # CLÉE : session réutilisée massivement
    d["label"]               = np.full(n, "SESSION_HIJACKING")
    return pd.DataFrame(d)


# ─────────────────────────────────────────────────────────────
# MAIN — Assemblage et export
# ─────────────────────────────────────────────────────────────
def add_noise(df, noise_level=0.02):
    """Ajoute un bruit gaussien léger sur les colonnes numériques pour plus de réalisme."""
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if "label" in numeric_cols:
        numeric_cols.remove("label")
    for col in numeric_cols:
        std = df[col].std()
        if std > 0:
            df[col] = df[col] + RNG.normal(0, std * noise_level, len(df))
            df[col] = df[col].clip(lower=0)
    return df

def generate_full_dataset():
    print("Generating dataset...")
    generators = {
        "BENIGN":           (gen_benign,           5000),
        "ARP_SPOOFING":     (gen_arp_spoofing,      800),
        "STP_SPOOFING":     (gen_stp_spoofing,      400),
        "MAC_FLOODING":     (gen_mac_flooding,      900),
        "DHCP_SPOOFING":    (gen_dhcp_spoofing,     600),
        "IP_SPOOFING":      (gen_ip_spoofing,       700),
        "SYN_FLOOD":        (gen_syn_flood,        1500),
        "DDOS":             (gen_ddos,             1500),
        "PORT_SCAN":        (gen_port_scan,        1000),
        "ROUTING_ATTACK":   (gen_routing_attack,    400),
        "SQL_INJECTION":    (gen_sql_injection,     700),
        "XSS":              (gen_xss,               700),
        "SSL_STRIPPING":    (gen_ssl_stripping,     500),
        "SESSION_HIJACKING":(gen_session_hijacking, 600),
    }

    frames = []
    total = 0
    for label, (fn, n) in generators.items():
        df = fn(n)
        df = add_noise(df)
        frames.append(df)
        total += n
        print(f"  ✓ {label:<22} {n:>5} flows")

    dataset = pd.concat(frames, ignore_index=True)
    dataset = dataset.sample(frac=1, random_state=42).reset_index(drop=True)

    # Encode label
    le = LabelEncoder()
    dataset["label_encoded"] = le.fit_transform(dataset["label"])

    # Round float columns
    float_cols = dataset.select_dtypes(include=[np.float64]).columns
    dataset[float_cols] = dataset[float_cols].round(4)

    # Ensure all non-negative
    numeric_cols = dataset.select_dtypes(include=[np.number]).columns
    dataset[numeric_cols] = dataset[numeric_cols].clip(lower=0)

    print(f"\nTotal: {total} flows | {dataset.shape[1]} features")
    print(f"\nDistribution:\n{dataset['label'].value_counts().to_string()}")

    # Stats quick check
    print("\nQuick sanity checks:")
    arp = dataset[dataset["label"] == "ARP_SPOOFING"]
    print(f"  ARP Spoofing  — arp_reply_ratio mean: {arp['arp_reply_ratio'].mean():.3f} (expected ~0.92)")
    syn = dataset[dataset["label"] == "SYN_FLOOD"]
    print(f"  SYN Flood     — syn_flag_count mean:  {syn['syn_flag_count'].mean():.0f} (expected high)")
    mac = dataset[dataset["label"] == "MAC_FLOODING"]
    print(f"  MAC Flooding  — unique_src_mac mean:  {mac['unique_src_mac'].mean():.0f} (expected ~5000)")
    sqli = dataset[dataset["label"] == "SQL_INJECTION"]
    print(f"  SQL Injection — has_sql_keyword mean: {sqli['has_sql_keyword'].mean():.2f} (expected 1.0)")

    return dataset, le

if __name__ == "__main__":
    import os
    os.makedirs("dataset", exist_ok=True)

    dataset, le = generate_full_dataset()

    # Export CSV principal
    out_path = "dataset/ids_onos_dataset.csv"
    dataset.to_csv(out_path, index=False)
    print(f"\nDataset saved → {out_path}")

    # Export train/test split
    from sklearn.model_selection import train_test_split
    train, test = train_test_split(dataset, test_size=0.2, random_state=42, stratify=dataset["label"])
    train.to_csv("dataset/train.csv", index=False)
    test.to_csv("dataset/test.csv", index=False)
    print(f"Train: {len(train)} | Test: {len(test)}")

    # Export label mapping
    import json
    label_map = {int(i): str(l) for i, l in enumerate(le.classes_)}
    with open("dataset/label_mapping.json", "w") as f:
        json.dump(label_map, f, indent=2)
    print(f"Label mapping → dataset/label_mapping.json")
    print("\nClasses:", list(le.classes_))
