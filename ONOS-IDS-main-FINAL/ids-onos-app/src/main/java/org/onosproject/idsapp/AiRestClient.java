package org.onosproject.idsapp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * AiRestClient
 *
 * Appelle le service FastAPI IDS via HTTP.
 * Utilise uniquement java.net (pas de dependance externe).
 *
 * Endpoints utilises :
 *   GET  /health        — verifie que le service est up
 *   POST /predict/batch — envoie les flux, recoit les predictions
 */
public class AiRestClient {

    private static final Logger log = LoggerFactory.getLogger(AiRestClient.class);

    private final String  baseUrl;      // ex: "http://localhost:8000"
    private final int     timeoutMs;    // timeout HTTP en ms
    private final ObjectMapper mapper;

    public AiRestClient(String baseUrl, int timeoutMs) {
        this.baseUrl   = baseUrl.replaceAll("/$", ""); // supprime le slash final
        this.timeoutMs = timeoutMs;
        this.mapper    = new ObjectMapper();
    }

    // ──────────────────────────────────────────────────────────────
    // Verifie que le service FastAPI est disponible
    // ──────────────────────────────────────────────────────────────
    public boolean isHealthy() {
        try {
            HttpURLConnection conn = openConnection(baseUrl + "/health", "GET");
            int code = conn.getResponseCode();
            conn.disconnect();
            if (code == 200) {
                log.debug("[AiRestClient] /health OK");
                return true;
            }
            log.warn("[AiRestClient] /health retourne HTTP {}", code);
            return false;
        } catch (Exception e) {
            log.warn("[AiRestClient] Service FastAPI inaccessible : {}", e.getMessage());
            return false;
        }
    }

    // ──────────────────────────────────────────────────────────────
    // Envoie un batch de flux et retourne les predictions
    // ──────────────────────────────────────────────────────────────
    public List<PredictionResult> predictBatch(List<FlowStatsCollector.FlowVector> flows) {
        List<PredictionResult> results = new ArrayList<>();

        if (flows.isEmpty()) {
            return results;
        }

        try {
            // ── Construit le JSON ──────────────────────────────────
            // Format : {"flows": [{"flow_id": "...", "features": [...]}, ...]}
            ObjectNode body    = mapper.createObjectNode();
            ArrayNode  flowArr = mapper.createArrayNode();

            for (FlowStatsCollector.FlowVector fv : flows) {
                ObjectNode flowNode = mapper.createObjectNode();
                flowNode.put("flow_id", fv.flowId);

                ArrayNode featArr = mapper.createArrayNode();
                for (double v : fv.features) {
                    featArr.add(Double.isNaN(v) || Double.isInfinite(v) ? 0.0 : v);
                }
                flowNode.set("features", featArr);
                flowArr.add(flowNode);
            }
            body.set("flows", flowArr);

            String jsonBody = mapper.writeValueAsString(body);
            log.debug("[AiRestClient] Envoi batch {} flux → /predict/batch", flows.size());

            // ── Appel HTTP POST ────────────────────────────────────
            HttpURLConnection conn = openConnection(baseUrl + "/predict/batch", "POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");

            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
            }

            int code = conn.getResponseCode();

            if (code != 200) {
                log.error("[AiRestClient] /predict/batch retourne HTTP {}", code);
                conn.disconnect();
                return results;
            }

            // ── Parse la reponse JSON ──────────────────────────────
            JsonNode response = mapper.readTree(conn.getInputStream());
            conn.disconnect();

            JsonNode resultArr = response.get("results");
            if (resultArr == null || !resultArr.isArray()) {
                log.warn("[AiRestClient] Reponse inattendue : {}", response);
                return results;
            }

            for (JsonNode r : resultArr) {
                String  flowId     = r.path("flow_id").asText("unknown");
                String  threat     = r.path("threat").asText("UNKNOWN");
                double  confidence = r.path("confidence").asDouble(0.0);
                String  action     = r.path("action").asText("ALLOW");
                double  latencyMs  = r.path("latency_ms").asDouble(0.0);

                results.add(new PredictionResult(flowId, threat, confidence, action, latencyMs));
            }

            log.debug("[AiRestClient] Reponse : {} predictions recues", results.size());

        } catch (IOException e) {
            log.error("[AiRestClient] Erreur HTTP : {}", e.getMessage());
        } catch (Exception e) {
            log.error("[AiRestClient] Erreur inattendue : {}", e.getMessage(), e);
        }

        return results;
    }

    // ──────────────────────────────────────────────────────────────
    // Ouvre une connexion HTTP avec timeout
    // ──────────────────────────────────────────────────────────────
    private HttpURLConnection openConnection(String urlStr, String method) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(timeoutMs);
        conn.setReadTimeout(timeoutMs);
        conn.setRequestProperty("Accept", "application/json");
        return conn;
    }

    // ──────────────────────────────────────────────────────────────
    // Conteneur immuable pour une prediction
    // ──────────────────────────────────────────────────────────────
    public static class PredictionResult {
        public final String flowId;
        public final String threat;
        public final double confidence;
        public final String action;       // "BLOCK" | "INSPECT" | "ALLOW"
        public final double latencyMs;

        public PredictionResult(String flowId, String threat,
                                 double confidence, String action,
                                 double latencyMs) {
            this.flowId     = flowId;
            this.threat     = threat;
            this.confidence = confidence;
            this.action     = action;
            this.latencyMs  = latencyMs;
        }

        public boolean isThreat() {
            return !"BENIGN".equals(threat);
        }

        @Override
        public String toString() {
            return String.format("[%s] threat=%-20s conf=%.2f action=%s (%.1fms)",
                    flowId, threat, confidence, action, latencyMs);
        }
    }
}
