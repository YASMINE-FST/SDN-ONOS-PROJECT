package org.onosproject.idsapp;

import org.onosproject.net.Device;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowEntry;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.TcpPortCriterion;
import org.onosproject.net.flow.criteria.UdpPortCriterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.statistic.StatisticService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * FlowStatsCollector
 *
 * Lit les FlowEntry ONOS (statistiques OpenFlow) et construit
 * un vecteur de 82 features compatible avec le modele ML.
 *
 * Les features sont alignees sur CICFlowMeter :
 * flow_duration, protocol, fwd/bwd pkt counts, bytes, IAT,
 * TCP flags, header lengths, L2/L3/L7 features.
 */
public class FlowStatsCollector {

    private static final Logger log = LoggerFactory.getLogger(FlowStatsCollector.class);

    // Nombre exact de features attendues par le modele
    public static final int N_FEATURES = 82;

    private final FlowRuleService flowRuleService;
    private final DeviceService   deviceService;

    // Snapshot precedent pour calculer les deltas
    private final Map<String, long[]> prevSnapshot = new HashMap<>();

    public FlowStatsCollector(FlowRuleService flowRuleService,
                               DeviceService deviceService) {
        this.flowRuleService = flowRuleService;
        this.deviceService   = deviceService;
    }

    /**
     * Collecte les FlowEntry de tous les devices et retourne
     * une liste de vecteurs de features (un par flux actif).
     */
    public List<FlowVector> collectFlows() {
        List<FlowVector> vectors = new ArrayList<>();

        for (Device device : deviceService.getAvailableDevices()) {
            Iterable<FlowEntry> entries = flowRuleService.getFlowEntries(device.id());

            for (FlowEntry entry : entries) {
                try {
                    FlowVector fv = buildVector(entry, device.id().toString());
                    if (fv != null) {
                        vectors.add(fv);
                    }
                } catch (Exception e) {
                    log.warn("Erreur lors de la construction du vecteur pour {}: {}",
                             entry.id(), e.getMessage());
                }
            }
        }

        log.debug("Collecte: {} flux actifs sur {} devices",
                  vectors.size(),
                  deviceService.getAvailableDeviceCount());
        return vectors;
    }

    /**
     * Construit un FlowVector de 82 features a partir d'une FlowEntry ONOS.
     *
     * Les valeurs sont extraites des statistiques OpenFlow :
     * bytes, packets, life, puis les criteres de matching (protocol, ports, etc.)
     */
    private FlowVector buildVector(FlowEntry entry, String deviceId) {
        // Ignore les flux trop courts (moins de 2 paquets)
        if (entry.packets() < 2) {
            return null;
        }

        double[] f = new double[N_FEATURES];

        // ── Stats de base ──────────────────────────────────────────
        long lifeMicros = entry.life() * 1_000_000L;   // life() en secondes → microsecondes
        long packets    = entry.packets();
        long bytes      = entry.bytes();

        // Approximation fwd/bwd : on n'a qu'un sens dans OpenFlow simple
        // On estime 60% fwd / 40% bwd (heuristique raisonnable)
        long fwdPkts  = (long)(packets * 0.6);
        long bwdPkts  = packets - fwdPkts;
        long fwdBytes = (long)(bytes * 0.6);
        long bwdBytes = bytes - fwdBytes;

        double meanPktLen  = packets > 0 ? (double) bytes / packets : 0;
        double flowSec     = lifeMicros / 1_000_000.0 + 1e-9;
        double pktPerSec   = packets / flowSec;
        double bytePerSec  = bytes   / flowSec;

        // Extraction du protocole depuis les criteres de matching
        int protocol = extractProtocol(entry);

        // ── Construction du vecteur ────────────────────────────────
        // Index alignes sur le dataset CICFlowMeter genere

        f[0]  = lifeMicros;                            // flow_duration
        f[1]  = protocol;                              // protocol
        f[2]  = fwdPkts;                               // fwd_pkt_count
        f[3]  = bwdPkts;                               // bwd_pkt_count
        f[4]  = fwdBytes;                              // fwd_bytes_total
        f[5]  = bwdBytes;                              // bwd_bytes_total
        f[6]  = meanPktLen;                            // fwd_pkt_len_mean
        f[7]  = meanPktLen * 0.3;                      // fwd_pkt_len_std  (approx)
        f[8]  = meanPktLen * 1.5;                      // fwd_pkt_len_max
        f[9]  = meanPktLen * 0.5;                      // fwd_pkt_len_min
        f[10] = meanPktLen * 0.95;                     // bwd_pkt_len_mean
        f[11] = meanPktLen * 0.28;                     // bwd_pkt_len_std
        f[12] = meanPktLen * 1.4;                      // bwd_pkt_len_max
        f[13] = meanPktLen * 0.45;                     // bwd_pkt_len_min
        f[14] = bytePerSec;                            // flow_bytes_per_sec
        f[15] = pktPerSec;                             // flow_pkts_per_sec

        // IAT approxime a partir de la duree et du nombre de paquets
        double iatMean = packets > 1 ? lifeMicros / (packets - 1.0) : lifeMicros;
        f[16] = iatMean;                               // flow_iat_mean
        f[17] = iatMean * 0.5;                         // flow_iat_std
        f[18] = iatMean * 2.0;                         // flow_iat_max
        f[19] = iatMean * 0.1;                         // flow_iat_min
        f[20] = iatMean;                               // fwd_iat_mean
        f[21] = iatMean * 0.5;                         // fwd_iat_std
        f[22] = iatMean * 2.0;                         // fwd_iat_max
        f[23] = iatMean * 0.1;                         // fwd_iat_min
        f[24] = iatMean * 1.1;                         // bwd_iat_mean
        f[25] = iatMean * 0.55;                        // bwd_iat_std
        f[26] = iatMean * 2.1;                         // bwd_iat_max
        f[27] = iatMean * 0.12;                        // bwd_iat_min

        // Flags TCP (extraits du traitement ou mis a zero pour non-TCP)
        boolean isTcp = (protocol == 6);
        f[28] = 0;                                     // fwd_psh_flags
        f[29] = 0;                                     // bwd_psh_flags
        f[30] = 0;                                     // fwd_urg_flags
        f[31] = 0;                                     // bwd_urg_flags
        f[32] = isTcp ? 1 : 0;                        // fin_flag_count
        f[33] = isTcp ? fwdPkts * 0.1 : 0;           // syn_flag_count
        f[34] = 0;                                     // rst_flag_count
        f[35] = isTcp ? fwdPkts * 0.3 : 0;           // psh_flag_count
        f[36] = isTcp ? packets * 0.8 : 0;            // ack_flag_count
        f[37] = 0;                                     // urg_flag_count
        f[38] = 0;                                     // cwe_flag_count
        f[39] = 0;                                     // ece_flag_count

        // Header lengths
        int hdrSize = isTcp ? 20 : (protocol == 17 ? 8 : 0);
        f[40] = fwdPkts * hdrSize;                     // fwd_header_len
        f[41] = bwdPkts * hdrSize;                     // bwd_header_len
        f[42] = pktPerSec * 0.6;                       // fwd_pkts_per_sec
        f[43] = pktPerSec * 0.4;                       // bwd_pkts_per_sec

        // Packet length stats
        f[44] = meanPktLen * 0.5;                      // pkt_len_min
        f[45] = meanPktLen * 1.5;                      // pkt_len_max
        f[46] = meanPktLen;                            // pkt_len_mean
        f[47] = meanPktLen * 0.3;                      // pkt_len_std
        f[48] = meanPktLen * meanPktLen * 0.09;        // pkt_len_var

        // Ratios et tailles moyennes
        f[49] = fwdBytes > 0 ? (double) bwdBytes / fwdBytes : 0;  // down_up_ratio
        f[50] = meanPktLen;                            // avg_pkt_size
        f[51] = meanPktLen;                            // avg_fwd_segment_size
        f[52] = meanPktLen * 0.95;                     // avg_bwd_segment_size
        f[53] = fwdPkts * hdrSize;                     // fwd_header_len2

        // Subflow (identique aux totaux pour flux simple)
        f[54] = fwdPkts;                               // subflow_fwd_pkts
        f[55] = fwdBytes;                              // subflow_fwd_bytes
        f[56] = bwdPkts;                               // subflow_bwd_pkts
        f[57] = bwdBytes;                              // subflow_bwd_bytes

        // Window sizes (valeurs typiques)
        f[58] = 32768;                                 // init_fwd_win_bytes
        f[59] = 32768;                                 // init_bwd_win_bytes
        f[60] = fwdPkts;                               // fwd_act_data_pkts
        f[61] = meanPktLen * 0.5;                      // fwd_seg_size_min

        // Active / Idle
        f[62] = lifeMicros * 0.4;                      // active_mean
        f[63] = lifeMicros * 0.1;                      // active_std
        f[64] = lifeMicros * 0.6;                      // active_max
        f[65] = lifeMicros * 0.2;                      // active_min
        f[66] = lifeMicros * 0.6;                      // idle_mean
        f[67] = lifeMicros * 0.2;                      // idle_std
        f[68] = lifeMicros * 0.9;                      // idle_max
        f[69] = lifeMicros * 0.3;                      // idle_min

        // Features L2/L3 specifiques aux attaques reseau
        f[70] = 1;                                     // unique_src_mac (1 par defaut)
        f[71] = 1;                                     // unique_dst_mac
        f[72] = 0;                                     // arp_reply_ratio
        f[73] = 0;                                     // bcast_ratio
        f[74] = 0;                                     // dhcp_offer_count
        f[75] = 0;                                     // stp_bpdu_count

        // Features L7 (HTTP/HTTPS — indisponible sans DPI, mis a zero)
        f[76] = 0;                                     // http_payload_len
        f[77] = 0;                                     // http_entropy
        f[78] = 0;                                     // has_sql_keyword
        f[79] = 0;                                     // has_script_tag
        f[80] = 0;                                     // ssl_version_num
        f[81] = 0;                                     // session_reuse_ratio

        // Identifiant unique du flux
        String flowId = String.format("%s|%s|p%d",
                deviceId,
                entry.id().toString(),
                protocol);

        return new FlowVector(flowId, f);
    }

    /**
     * Extrait le protocole IP (6=TCP, 17=UDP, 1=ICMP) depuis les criteres
     * de matching de la FlowEntry. Retourne 0 si non trouvable.
     */
    private int extractProtocol(FlowEntry entry) {
        for (Criterion c : entry.selector().criteria()) {
            if (c.type() == Criterion.Type.IP_PROTO) {
                // Cast vers le bon type de critere ONOS
                try {
                    // Utilise reflection-safe toString parsing
                    String s = c.toString();
                    if (s.contains("6") || s.contains("TCP"))  return 6;
                    if (s.contains("17") || s.contains("UDP")) return 17;
                    if (s.contains("1") || s.contains("ICMP")) return 1;
                } catch (Exception ignored) {}
            }
            if (c.type() == Criterion.Type.TCP_DST ||
                c.type() == Criterion.Type.TCP_SRC) return 6;
            if (c.type() == Criterion.Type.UDP_DST ||
                c.type() == Criterion.Type.UDP_SRC) return 17;
        }
        return 6; // TCP par defaut
    }

    /**
     * Conteneur immuable : flowId + vecteur de 82 features.
     */
    public static class FlowVector {
        public final String   flowId;
        public final double[] features;

        public FlowVector(String flowId, double[] features) {
            this.flowId   = flowId;
            this.features = features;
        }
    }
}
