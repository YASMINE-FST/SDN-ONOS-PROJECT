"""
predictor.py
Logique ML pure — charge les modeles et fait les predictions.
Ne connait pas HTTP, peut etre teste seul.
"""
import os, time
import joblib
import numpy as np
from pathlib import Path
from typing import List, Dict, Any

MODEL_DIR            = Path(os.environ.get("MODEL_DIR", Path(__file__).parent / "models"))
CONFIDENCE_THRESHOLD = float(os.environ.get("CONFIDENCE_THRESHOLD", "0.85"))
N_FEATURES           = 82

KNOWN_CLASSES = [
    "ARP_SPOOFING", "BENIGN", "DDOS", "DHCP_SPOOFING", "IP_SPOOFING",
    "MAC_FLOODING", "PORT_SCAN", "ROUTING_ATTACK", "STP_SPOOFING", "SYN_FLOOD",
]

def decide_action(threat: str, confidence: float) -> str:
    """
    Regle metier : threat + confidence -> action recommandee.
      BENIGN             -> ALLOW  (peu importe la confidence)
      confidence >= 0.85 -> BLOCK
      confidence >= 0.60 -> INSPECT
      sinon              -> ALLOW  (trop incertain, evite faux positifs)
    """
    if threat == "BENIGN":
        return "ALLOW"
    if confidence >= CONFIDENCE_THRESHOLD:
        return "BLOCK"
    if confidence >= 0.60:
        return "INSPECT"
    return "ALLOW"


class IDSPredictor:
    """
    Encapsule RF + scaler + label_encoder.
    Instance unique (singleton) partagee par FastAPI.
    """

    def __init__(self):
        self.model         = None
        self.scaler        = None
        self.label_encoder = None
        self.is_loaded     = False
        self._start_time   = None
        self._n_calls      = 0
        self._total_ms     = 0.0

    # ------------------------------------------------------------------
    def load(self, model_dir: Path = None) -> None:
        """Charge les 3 fichiers .pkl depuis model_dir."""
        d = model_dir or MODEL_DIR
        self.model         = joblib.load(d / "model_rf.pkl")
        self.scaler        = joblib.load(d / "scaler.pkl")
        self.label_encoder = joblib.load(d / "label_encoder.pkl")
        self.is_loaded     = True
        self._start_time   = time.time()
        print(f"[IDSPredictor] charge depuis {d}")
        print(f"  modele   : {type(self.model).__name__}")
        print(f"  features : {self.model.n_features_in_}")
        print(f"  classes  : {list(self.label_encoder.classes_)}")

    # ------------------------------------------------------------------
    def _check(self):
        if not self.is_loaded:
            raise RuntimeError("Modeles non charges. Appelle load() d'abord.")

    def _clean(self, arr: np.ndarray) -> np.ndarray:
        """Remplace NaN et Inf par 0 pour eviter les crashes."""
        return np.nan_to_num(arr, nan=0.0, posinf=0.0, neginf=0.0)

    # ------------------------------------------------------------------
    def predict_one(self, features: List[float]) -> Dict[str, Any]:
        """
        Predit le type d'un seul flux reseau.

        Parametre : features — liste de 82 floats
        Retourne  : {"threat", "confidence", "action", "latency_ms"}
        """
        self._check()
        if len(features) != N_FEATURES:
            raise ValueError(f"Expected {N_FEATURES} features, got {len(features)}")

        t0 = time.perf_counter()

        X        = self._clean(np.array(features, dtype=float).reshape(1, -1))
        X_scaled = self.scaler.transform(X)
        idx      = self.model.predict(X_scaled)[0]
        proba    = self.model.predict_proba(X_scaled)[0]

        confidence = float(proba.max())
        threat     = str(self.label_encoder.inverse_transform([idx])[0])
        action     = decide_action(threat, confidence)
        latency_ms = (time.perf_counter() - t0) * 1000

        self._n_calls  += 1
        self._total_ms += latency_ms

        return {
            "threat":     threat,
            "confidence": round(confidence, 4),
            "action":     action,
            "latency_ms": round(latency_ms, 3),
        }

    # ------------------------------------------------------------------
    def predict_batch(self, batch: List[List[float]]) -> List[Dict[str, Any]]:
        """
        Predit plusieurs flux d'un coup (vectorise = plus rapide).

        Parametre : batch — liste de listes de 82 floats
        Retourne  : liste de {"flow_index", "threat", "confidence", "action", "latency_ms"}
        """
        self._check()
        for i, f in enumerate(batch):
            if len(f) != N_FEATURES:
                raise ValueError(f"Flux #{i}: expected {N_FEATURES} features, got {len(f)}")

        t0       = time.perf_counter()
        X        = self._clean(np.array(batch, dtype=float))
        X_scaled = self.scaler.transform(X)
        idxs     = self.model.predict(X_scaled)
        probas   = self.model.predict_proba(X_scaled)
        total_ms = (time.perf_counter() - t0) * 1000
        per_ms   = total_ms / len(batch)

        results = []
        for i, (idx, proba) in enumerate(zip(idxs, probas)):
            confidence = float(proba.max())
            threat     = str(self.label_encoder.inverse_transform([idx])[0])
            results.append({
                "flow_index": i,
                "threat":     threat,
                "confidence": round(confidence, 4),
                "action":     decide_action(threat, confidence),
                "latency_ms": round(per_ms, 3),
            })

        self._n_calls  += len(batch)
        self._total_ms += total_ms
        return results

    # ------------------------------------------------------------------
    def stats(self) -> Dict[str, Any]:
        """Metriques internes pour l'endpoint /metrics."""
        avg = self._total_ms / self._n_calls if self._n_calls > 0 else 0.0
        return {
            "model_loaded":   self.is_loaded,
            "predict_count":  self._n_calls,
            "avg_latency_ms": round(avg, 3),
            "uptime_s":       round(time.time() - self._start_time, 1)
                              if self._start_time else 0,
        }


# Singleton global utilise par main.py
predictor = IDSPredictor()
