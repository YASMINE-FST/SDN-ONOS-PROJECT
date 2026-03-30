"""
main.py
Serveur FastAPI IDS — version 2 avec Risk Score dynamique.

Nouveaux endpoints (inspire Huawei iMaster) :
  GET  /risk/{ip}     — score de risque glissant pour une IP
  GET  /risk/summary  — resume toutes les IPs trackees
  GET  /risk/top      — top 10 IPs les plus dangereuses

Demarrage :
    cd ~/onos_open/ids_service
    uvicorn main:app --host 0.0.0.0 --port 8000
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
from risk_score import risk_engine


# ── Lifespan ──────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    model_dir = Path(os.environ.get("MODEL_DIR", str(MODEL_DIR)))
    print(f"[startup] Chargement modeles depuis {model_dir} ...")
    try:
        predictor.load(model_dir)
        print("[startup] OK — service pret")
        print(f"[startup] Risk Score engine demarre — fenetre 5 minutes")
    except FileNotFoundError as e:
        print(f"[startup] ERREUR : {e}")
    yield
    print("[shutdown] Service arrete")


# ── Application ───────────────────────────────────────────────────
app = FastAPI(
    title="IDS ONOS — AI Service v2",
    description="Detection d'intrusion + Risk Score dynamique (Huawei iMaster inspired)",
    version="2.0.0",
    lifespan=lifespan,
)


# ── Middleware log ────────────────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    t0       = time.perf_counter()
    response = await call_next(request)
    ms       = (time.perf_counter() - t0) * 1000
    print(f"  [{request.method}] {request.url.path} -> {response.status_code} ({ms:.1f}ms)")
    return response


# ══════════════════════════════════════════════════════════════════
# GET /health
# ══════════════════════════════════════════════════════════════════
@app.get("/health", response_model=HealthResponse)
def health():
    n_classes = len(predictor.label_encoder.classes_) if predictor.is_loaded else 0
    return HealthResponse(
        status       = "ok" if predictor.is_loaded else "degraded",
        model_loaded = predictor.is_loaded,
        n_features   = N_FEATURES,
        n_classes    = n_classes,
    )


# ══════════════════════════════════════════════════════════════════
# POST /predict
# ══════════════════════════════════════════════════════════════════
@app.post("/predict", response_model=FlowResponse)
def predict(req: FlowRequest):
    if not predictor.is_loaded:
        raise HTTPException(503, detail="Modeles non charges.")
    try:
        result = predictor.predict_one(req.features)
    except ValueError as e:
        raise HTTPException(422, detail=str(e))
    except Exception as e:
        raise HTTPException(500, detail=f"Erreur prediction : {e}")

    # Enregistre dans le risk engine
    risk_engine.record_alert(
        ip=req.flow_id,
        threat=result["threat"],
        confidence=result["confidence"],
        flow_id=req.flow_id,
    )

    return FlowResponse(
        flow_id    = req.flow_id,
        threat     = result["threat"],
        confidence = result["confidence"],
        action     = result["action"],
        latency_ms = result["latency_ms"],
    )


# ══════════════════════════════════════════════════════════════════
# POST /predict/batch
# ══════════════════════════════════════════════════════════════════
@app.post("/predict/batch", response_model=BatchResponse)
def predict_batch(req: BatchRequest):
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
        # Enregistre dans le risk engine
        risk_engine.record_alert(
            ip=req.flows[i].flow_id,
            threat=r["threat"],
            confidence=r["confidence"],
            flow_id=req.flows[i].flow_id,
        )

    return BatchResponse(
        results       = results,
        total_flows   = len(results),
        batch_time_ms = round((time.perf_counter() - t0) * 1000, 3),
    )


# ══════════════════════════════════════════════════════════════════
# GET /metrics
# ══════════════════════════════════════════════════════════════════
@app.get("/metrics", response_model=MetricsResponse)
def metrics():
    return MetricsResponse(**predictor.stats())


# ══════════════════════════════════════════════════════════════════
# GET /risk/{ip}   — Risk Score d'une IP specifique
# Inspire Huawei iMaster NCE
# ══════════════════════════════════════════════════════════════════
@app.get("/risk/{ip:path}")
def risk_by_ip(ip: str):
    """
    Retourne le score de risque glissant (5 min) pour une IP/deviceId.

    Exemple : GET /risk/192.168.1.10
              GET /risk/of:0000000000000001
    """
    score = risk_engine.get_score(ip)
    return score


# ══════════════════════════════════════════════════════════════════
# GET /risk/summary   — Resume toutes les IPs trackees
# ══════════════════════════════════════════════════════════════════
@app.get("/risk/summary")
def risk_summary():
    """
    Retourne le resume de toutes les IPs avec alertes dans les 5 dernieres minutes.
    Trie par score decroissant.
    """
    summary = risk_engine.get_summary()
    return {
        "total_tracked":  risk_engine.total_tracked(),
        "critical_count": len(risk_engine.critical_ips()),
        "window_minutes": 5,
        "ips":            summary,
    }


# ══════════════════════════════════════════════════════════════════
# GET /risk/top   — Top 10 IPs les plus dangereuses
# ══════════════════════════════════════════════════════════════════
@app.get("/risk/top")
def risk_top():
    """Top 10 IPs les plus dangereuses dans la fenetre glissante."""
    return {
        "top_threats": risk_engine.get_top_threats(10),
        "critical_ips": risk_engine.critical_ips(),
    }


# ── Erreur globale ────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_error_handler(request: Request, exc: Exception):
    print(f"[ERREUR] {request.url.path} — {type(exc).__name__}: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Erreur interne", "error": str(exc)},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
