package org.onosproject.idsapp;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.device.DeviceService;
import org.onosproject.net.flow.FlowRuleService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * IdsAppComponent
 *
 * Composant principal de l'application IDS pour ONOS.
 *
 * Cycle de vie :
 *   @Activate  → enregistre l'app, demarre le scheduler toutes les 2s
 *   @Deactivate → arrete proprement le scheduler
 *
 * Boucle de detection (toutes les 2s) :
 *   1. Collecte les FlowEntry via FlowStatsCollector
 *   2. Envoie en batch au service FastAPI via AiRestClient
 *   3. Pour chaque prediction : AlertManager.process()
 *   4. Toutes les 60s : AlertManager.logStats()
 *
 * Configuration :
 *   AI_SERVICE_URL — URL du service FastAPI (defaut: http://localhost:8000)
 *   POLL_INTERVAL_S — intervalle de collecte en secondes (defaut: 2)
 */
@Component(immediate = true)
public class IdsAppComponent {

    private static final Logger log = LoggerFactory.getLogger(IdsAppComponent.class);

    // ── Configuration ──────────────────────────────────────────────
    private static final String AI_SERVICE_URL  =
            System.getProperty("ids.ai.url", "http://localhost:8000");
    private static final int    POLL_INTERVAL_S =
            Integer.parseInt(System.getProperty("ids.poll.interval", "2"));
    private static final int    HTTP_TIMEOUT_MS = 5000;   // 5s timeout FastAPI
    private static final int    STATS_INTERVAL_S = 60;    // resume alertes toutes les 60s

    // ── Services ONOS injectes par OSGi ───────────────────────────
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected DeviceService deviceService;

    // ── Composants internes ───────────────────────────────────────
    private ApplicationId         appId;
    private FlowStatsCollector    collector;
    private AiRestClient          aiClient;
    private AlertManager          alertManager;
    private ScheduledExecutorService scheduler;

    private final AtomicBoolean aiAvailable  = new AtomicBoolean(false);
    private long                cycleCount   = 0;

    // ══════════════════════════════════════════════════════════════
    // ACTIVATE — demarre quand ONOS charge l'app
    // ══════════════════════════════════════════════════════════════
    @Activate
    protected void activate() {
        // Enregistre l'app aupres du CoreService ONOS
        appId = coreService.registerApplication("org.onosproject.idsapp");

        // Initialise les composants
        collector    = new FlowStatsCollector(flowRuleService, deviceService);
        aiClient     = new AiRestClient(AI_SERVICE_URL, HTTP_TIMEOUT_MS);
        alertManager = new AlertManager();

        // Verifie la disponibilite du service FastAPI au demarrage
        aiAvailable.set(aiClient.isHealthy());
        if (aiAvailable.get()) {
            log.info("[IDS] Service FastAPI disponible sur {}", AI_SERVICE_URL);
        } else {
            log.warn("[IDS] Service FastAPI INDISPONIBLE sur {} — les alertes seront desactivees",
                     AI_SERVICE_URL);
            log.warn("[IDS] Demarre ton service : uvicorn main:app --host 0.0.0.0 --port 8000");
        }

        // Demarre le scheduler
        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ids-detection-loop");
            t.setDaemon(true);
            return t;
        });
        scheduler.scheduleAtFixedRate(
                this::detectionCycle,
                5,                   // delai initial : 5s (laisse ONOS se stabiliser)
                POLL_INTERVAL_S,
                TimeUnit.SECONDS
        );

        log.info("[IDS] ╔══════════════════════════════════════════════╗");
        log.info("[IDS] ║  IDS App activee                            ║");
        log.info("[IDS] ║  AppId      : {}                    ║", appId.id());
        log.info("[IDS] ║  AI Service : {}     ║", AI_SERVICE_URL);
        log.info("[IDS] ║  Intervalle : {}s                          ║", POLL_INTERVAL_S);
        log.info("[IDS] ║  Mode       : ALERTE UNIQUEMENT (pas block)║");
        log.info("[IDS] ╚══════════════════════════════════════════════╝");
    }

    // ══════════════════════════════════════════════════════════════
    // DEACTIVATE — arrete proprement quand ONOS retire l'app
    // ══════════════════════════════════════════════════════════════
    @Deactivate
    protected void deactivate() {
        if (scheduler != null && !scheduler.isShutdown()) {
            scheduler.shutdown();
            try {
                scheduler.awaitTermination(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
        alertManager.logStats();
        log.info("[IDS] Application desactivee — {} cycles effectues", cycleCount);
    }

    // ══════════════════════════════════════════════════════════════
    // BOUCLE DE DETECTION — appelee toutes les POLL_INTERVAL_S secondes
    // ══════════════════════════════════════════════════════════════
    private void detectionCycle() {
        cycleCount++;

        try {
            // ── 1. Verifie periodiquement que FastAPI est up ───────
            if (cycleCount % 15 == 0) { // toutes les 30s (15 * 2s)
                boolean healthy = aiClient.isHealthy();
                if (healthy != aiAvailable.get()) {
                    aiAvailable.set(healthy);
                    if (healthy) {
                        log.info("[IDS] Service FastAPI de nouveau disponible");
                    } else {
                        log.warn("[IDS] Service FastAPI est devenu indisponible");
                    }
                }
            }

            if (!aiAvailable.get()) {
                return; // FastAPI down, on attend
            }

            // ── 2. Collecte les flux actifs ────────────────────────
            List<FlowStatsCollector.FlowVector> flows = collector.collectFlows();

            if (flows.isEmpty()) {
                log.debug("[IDS] Cycle {} : aucun flux actif", cycleCount);
                return;
            }

            log.debug("[IDS] Cycle {} : {} flux collectes", cycleCount, flows.size());

            // ── 3. Envoie au service FastAPI ───────────────────────
            List<AiRestClient.PredictionResult> predictions =
                    aiClient.predictBatch(flows);

            if (predictions.isEmpty()) {
                return;
            }

            // ── 4. Traite chaque prediction ────────────────────────
            long threats = 0;
            for (AiRestClient.PredictionResult pred : predictions) {
                alertManager.process(pred);
                if (pred.isThreat()) {
                    threats++;
                }
            }

            if (threats > 0) {
                log.info("[IDS] Cycle {} : {}/{} flux suspects",
                         cycleCount, threats, predictions.size());
            }

            // ── 5. Resume stats toutes les 60s ────────────────────
            long secondsElapsed = cycleCount * POLL_INTERVAL_S;
            if (secondsElapsed % STATS_INTERVAL_S == 0) {
                alertManager.logStats();
            }

        } catch (Exception e) {
            log.error("[IDS] Erreur dans le cycle de detection #{} : {}",
                      cycleCount, e.getMessage(), e);
        }
    }
}
