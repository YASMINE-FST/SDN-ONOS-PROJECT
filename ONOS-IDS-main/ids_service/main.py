"""
main.py
Serveur FastAPI IDS — pont entre ONOS (Java) et les modeles Python.

Demarrage sur ta VM :
    cd ~/onos_open/ids_service
    uvicorn main:app --host 0.0.0.0 --port 8000

ONOS appellera ensuite :
    POST http://localhost:8000/predict
    {"flow_id": "...", "features": [82 valeurs]}
"""
import os, time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from schemas import (
    FlowRequest, FlowResponse,
    BatchRequest, BatchResponse,
    HealthResponse, MetricsResponse,
    N_FEATURES,
)
from predictor import predictor, MODEL_DIR


# ── Lifespan : charge les modeles au demarrage ────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    model_dir = Path(os.environ.get("MODEL_DIR", str(MODEL_DIR)))
    print(f"[startup] Chargement des modeles depuis {model_dir} ...")
    try:
        predictor.load(model_dir)
        print("[startup] OK — service pret")
    except FileNotFoundError as e:
        print(f"[startup] ERREUR : {e}")
        print("[startup] /predict retournera 503 tant que les modeles ne sont pas charges")
    yield
    print("[shutdown] Service arrete")


# ── Application ───────────────────────────────────────────────────
app = FastAPI(
    title="IDS ONOS — AI Service",
    description="Detection d'intrusion temps reel pour SDN ONOS. 14 classes d'attaques.",
    version="1.0.0",
    lifespan=lifespan,
)


# ── Middleware : log chaque requete ───────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    t0       = time.perf_counter()
    response = await call_next(request)
    ms       = (time.perf_counter() - t0) * 1000
    print(f"  [{request.method}] {request.url.path} -> {response.status_code}  ({ms:.1f}ms)")
    return response


# ════════════════════════════════════════════════════════════════════
# GET /health
# ONOS appelle ca au demarrage pour verifier que l'IA est disponible
# ════════════════════════════════════════════════════════════════════
@app.get("/health", response_model=HealthResponse)
def health():
    """Verifie que le service et les modeles sont operationnels."""
    n_classes = len(predictor.label_encoder.classes_) if predictor.is_loaded else 0
    return HealthResponse(
        status       = "ok" if predictor.is_loaded else "degraded",
        model_loaded = predictor.is_loaded,
        n_features   = N_FEATURES,
        n_classes    = n_classes,
    )


# ════════════════════════════════════════════════════════════════════
# POST /predict   <- endpoint principal
# ONOS envoie 82 features d'un flux suspect, on repond en <10ms
# ════════════════════════════════════════════════════════════════════
@app.post("/predict", response_model=FlowResponse)
def predict(req: FlowRequest):
    """
    Analyse un flux reseau et retourne :
    - threat     : SYN_FLOOD | DDOS | ARP_SPOOFING | ... | BENIGN
    - confidence : probabilite entre 0.0 et 1.0
    - action     : BLOCK (>=0.85) | INSPECT (>=0.60) | ALLOW
    - latency_ms : temps de prediction ML en millisecondes
    """
    if not predictor.is_loaded:
        raise HTTPException(503, detail="Modeles non charges. Service indisponible.")
    try:
        result = predictor.predict_one(req.features)
    except ValueError as e:
        raise HTTPException(422, detail=str(e))
    except Exception as e:
        raise HTTPException(500, detail=f"Erreur de prediction : {e}")

    return FlowResponse(
        flow_id    = req.flow_id,
        threat     = result["threat"],
        confidence = result["confidence"],
        action     = result["action"],
        latency_ms = result["latency_ms"],
    )


# ════════════════════════════════════════════════════════════════════
# POST /predict/batch
# ONOS collecte les stats toutes les 2s -> plusieurs flux d'un coup
# ════════════════════════════════════════════════════════════════════
@app.post("/predict/batch", response_model=BatchResponse)
def predict_batch(req: BatchRequest):
    """Analyse jusqu'a 500 flux en une seule requete HTTP."""
    if not predictor.is_loaded:
        raise HTTPException(503, detail="Modeles non charges.")

    t0 = time.perf_counter()
    try:
        results = predictor.predict_batch([f.features for f in req.flows])
    except ValueError as e:
        raise HTTPException(422, detail=str(e))
    except Exception as e:
        raise HTTPException(500, detail=f"Erreur batch : {e}")

    for i, r in enumerate(results):
        r["flow_id"] = req.flows[i].flow_id

    return BatchResponse(
        results       = results,
        total_flows   = len(results),
        batch_time_ms = round((time.perf_counter() - t0) * 1000, 3),
    )


# ════════════════════════════════════════════════════════════════════
# GET /metrics
# Consomme par Grafana pour monitorer le service
# ════════════════════════════════════════════════════════════════════
@app.get("/metrics", response_model=MetricsResponse)
def metrics():
    """Retourne : nb predictions, latence moyenne, uptime."""
    return MetricsResponse(**predictor.stats())


# ── Gestionnaire d'erreurs global ─────────────────────────────────
@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    print(f"[ERREUR] {request.url.path} — {type(exc).__name__}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Erreur interne", "error": str(exc)},
    )


# ── Lancement direct (dev) ────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
