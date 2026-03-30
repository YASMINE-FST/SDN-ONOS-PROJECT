"""
schemas.py
Format JSON des requetes et reponses.
FastAPI valide automatiquement chaque requete contre ces schemas.
"""
from pydantic import BaseModel, Field, field_validator
from typing import List

N_FEATURES = 82


# ── Requetes (ce qu'ONOS envoie) ──────────────────────────────────

class FlowRequest(BaseModel):
    """Un seul flux reseau a analyser."""
    flow_id:  str         = Field(..., description="ID du flux, ex: 192.168.1.5:1234->10.0.0.1:80")
    features: List[float] = Field(..., description=f"Exactement {N_FEATURES} features CICFlowMeter")

    @field_validator("features")
    @classmethod
    def check_len(cls, v):
        if len(v) != N_FEATURES:
            raise ValueError(f"Exactement {N_FEATURES} features attendues, recu {len(v)}")
        return v


class BatchRequest(BaseModel):
    """Plusieurs flux en une seule requete (max 500)."""
    flows: List[FlowRequest] = Field(..., min_length=1, max_length=500)


# ── Reponses (ce que le service renvoie) ──────────────────────────

class FlowResponse(BaseModel):
    """Reponse pour un flux unique."""
    flow_id:    str
    threat:     str   = Field(description="Ex: SYN_FLOOD, BENIGN, DDOS...")
    confidence: float = Field(ge=0.0, le=1.0)
    action:     str   = Field(description="BLOCK | INSPECT | ALLOW")
    latency_ms: float


class BatchResponse(BaseModel):
    """Reponse pour un batch."""
    results:       List[dict]
    total_flows:   int
    batch_time_ms: float


class HealthResponse(BaseModel):
    status:       str    # "ok" | "degraded"
    model_loaded: bool
    n_features:   int
    n_classes:    int
    version:      str = "1.0.0"


class MetricsResponse(BaseModel):
    model_loaded:   bool
    predict_count:  int
    avg_latency_ms: float
    uptime_s:       float
