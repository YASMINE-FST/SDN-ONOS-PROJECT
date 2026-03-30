package org.onosproject.idsapp;

import org.onosproject.net.device.DeviceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * AlertManager
 *
 * Gere les alertes de securite — LOG uniquement, aucun blocage.
 *
 * Pour chaque detection :
 *   - Log dans les logs ONOS (visible via "log:tail" dans la CLI ONOS)
 *   - Compte les alertes par type d'attaque
 *   - Evite le spam : cooldown de 30s par flow_id
 *
 * Design : alerte = visibilite. La decision de bloquer appartient
 * a l'operateur humain via la CLI ONOS ou l'interface web.
 */
public class AlertManager {

    private static final Logger log = LoggerFactory.getLogger(AlertManager.class);

    // Formatter pour l'horodatage lisible
    private static final DateTimeFormatter FMT = DateTimeFormatter
            .ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.systemDefault());

    // Cooldown : un flow_id ne genere qu'une alerte toutes les 30s
    private static final long COOLDOWN_MS = 30_000;

    // Derniere alerte par flow_id (timestamp ms)
    private final Map<String, Long> lastAlertTime = new ConcurrentHashMap<>();

    // Compteurs par type d'attaque
    private final Map<String, AtomicLong> alertCounts = new ConcurrentHashMap<>();

    // Compteur total
    private final AtomicLong totalAlerts = new AtomicLong(0);

    // ──────────────────────────────────────────────────────────────
    // Traite une prediction et emet une alerte si necessaire
    // ──────────────────────────────────────────────────────────────
    public void process(AiRestClient.PredictionResult result) {
        // Ignore les flux benins
        if (!result.isThreat()) {
            return;
        }

        // Applique le cooldown
        long now = System.currentTimeMillis();
        Long last = lastAlertTime.get(result.flowId);
        if (last != null && (now - last) < COOLDOWN_MS) {
            return; // alerte recente pour ce flux, on ignore
        }
        lastAlertTime.put(result.flowId, now);

        // Incremente les compteurs
        totalAlerts.incrementAndGet();
        alertCounts.computeIfAbsent(result.threat, k -> new AtomicLong(0))
                   .incrementAndGet();

        // ── Alerte dans les logs ONOS ──────────────────────────────
        // Visible via : log:tail dans la CLI ONOS
        //            ou : tail -f /opt/onos/var/log/karaf.log
        String timestamp = FMT.format(Instant.now());
        String level     = getAlertLevel(result.confidence);

        log.warn("╔══════════════════════════════════════════════════════╗");
        log.warn("║  [IDS ALERT] {} - {} ║", timestamp, level);
        log.warn("╠══════════════════════════════════════════════════════╣");
        log.warn("║  Flow      : {}", result.flowId);
        log.warn("║  Threat    : {}", result.threat);
        log.warn("║  Confidence: {}", String.format("%.1f%%", result.confidence * 100));
        log.warn("║  Action    : {} (alerte uniquement — pas de blocage)", result.action);
        log.warn("║  Latency   : {}ms", String.format("%.1f", result.latencyMs));
        log.warn("║  Total     : {} alertes depuis le demarrage", totalAlerts.get());
        log.warn("╚══════════════════════════════════════════════════════╝");

        // Alerte supplementaire pour les hautes confidences
        if (result.confidence >= 0.85) {
            log.error("[IDS HIGH-CONFIDENCE] {} detected on flow {} (conf={:.2f})",
                    result.threat, result.flowId, result.confidence);
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Affiche un resume des statistiques d'alertes dans les logs
    // ──────────────────────────────────────────────────────────────
    public void logStats() {
        if (totalAlerts.get() == 0) {
            log.info("[IDS Stats] Aucune menace detectee depuis le demarrage");
            return;
        }

        log.info("[IDS Stats] ═══ Resume alertes ═══");
        log.info("[IDS Stats] Total alertes : {}", totalAlerts.get());
        alertCounts.entrySet().stream()
                .sorted((a, b) -> Long.compare(b.getValue().get(), a.getValue().get()))
                .forEach(e -> log.info("[IDS Stats]   {:20s} : {} alertes",
                        e.getKey(), e.getValue().get()));
    }

    // ──────────────────────────────────────────────────────────────
    // Retourne le niveau d'alerte selon la confidence
    // ──────────────────────────────────────────────────────────────
    private String getAlertLevel(double confidence) {
        if (confidence >= 0.90) return "CRITIQUE";
        if (confidence >= 0.75) return "ELEVE   ";
        if (confidence >= 0.60) return "MOYEN   ";
        return                         "FAIBLE  ";
    }

    // ──────────────────────────────────────────────────────────────
    // Getters pour exposition via CLI ONOS
    // ──────────────────────────────────────────────────────────────
    public long getTotalAlerts() {
        return totalAlerts.get();
    }

    public Map<String, AtomicLong> getAlertCounts() {
        return alertCounts;
    }

    public void reset() {
        lastAlertTime.clear();
        alertCounts.clear();
        totalAlerts.set(0);
        log.info("[IDS AlertManager] Compteurs reinitialises");
    }
}
