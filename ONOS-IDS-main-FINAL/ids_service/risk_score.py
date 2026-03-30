"""
risk_score.py
Inspire de Huawei iMaster NCE — Risk Score dynamique par IP dans FastAPI.

Maintient un compteur glissant d'alertes par IP sur une fenetre de 5 minutes.
Expose via /risk/{ip} et /risk/summary.

Score calcule :
  - Chaque alerte ajoute des points selon le type d'attaque
  - Fenetre glissante de 5 minutes — les alertes expirent automatiquement
  - Score normalise entre 0 et 100

Integre dans main.py — appele par predictor apres chaque prediction positive.
"""
import time
from collections import defaultdict, deque
from threading import Lock
from typing import Dict, List, Optional
from dataclasses import dataclass, field

# ── Fenetre glissante ─────────────────────────────────────────────
WINDOW_SECONDS = 300  # 5 minutes

# ── Points par type d'attaque ─────────────────────────────────────
ATTACK_POINTS = {
    "SYN_FLOOD":         30,
    "DDOS":              30,
    "ROUTING_ATTACK":    30,
    "ARP_SPOOFING":      20,
    "MAC_FLOODING":      20,
    "DHCP_SPOOFING":     20,
    "STP_SPOOFING":      20,
    "PORT_SCAN":         10,
    "IP_SPOOFING":       15,
    "SQL_INJECTION":     15,
    "XSS":               15,
    "SESSION_HIJACKING": 15,
    "SSL_STRIPPING":     15,
}

# ── Niveaux de risque ─────────────────────────────────────────────
def compute_level(score: float) -> str:
    if score >= 86: return "CRITICAL"
    if score >= 61: return "HIGH"
    if score >= 31: return "MEDIUM"
    return "LOW"


@dataclass
class AlertEvent:
    """Un evenement d'alerte avec horodatage."""
    threat:     str
    confidence: float
    flow_id:    str
    points:     int
    timestamp:  float = field(default_factory=time.time)


class RiskScoreEngine:
    """
    Moteur de Risk Score par IP avec fenetre glissante.

    Thread-safe — utilise un Lock pour les acces concurrents.
    """

    def __init__(self, window_seconds: int = WINDOW_SECONDS):
        self.window_seconds = window_seconds
        # ip → deque d'AlertEvent dans la fenetre
        self._windows: Dict[str, deque] = defaultdict(deque)
        self._lock = Lock()

    # ──────────────────────────────────────────────────────────────
    def record_alert(self, ip: str, threat: str,
                     confidence: float, flow_id: str) -> dict:
        """
        Enregistre une alerte et retourne le score mis a jour.

        Parametre ip : identifiant de la source (IP ou deviceId)
        """
        if threat == "BENIGN":
            return self.get_score(ip)

        points = ATTACK_POINTS.get(threat, 15)
        event  = AlertEvent(
            threat=threat,
            confidence=confidence,
            flow_id=flow_id,
            points=points
        )

        with self._lock:
            self._windows[ip].append(event)
            self._cleanup(ip)
            return self._compute_score(ip)

    # ──────────────────────────────────────────────────────────────
    def get_score(self, ip: str) -> dict:
        """Retourne le score actuel d'une IP."""
        with self._lock:
            self._cleanup(ip)
            return self._compute_score(ip)

    # ──────────────────────────────────────────────────────────────
    def get_summary(self) -> List[dict]:
        """Retourne le resume de toutes les IPs trackees."""
        result = []
        with self._lock:
            for ip in list(self._windows.keys()):
                self._cleanup(ip)
                if self._windows[ip]:
                    result.append(self._compute_score(ip))
        # Trie par score decroissant
        result.sort(key=lambda x: x["score"], reverse=True)
        return result

    # ──────────────────────────────────────────────────────────────
    def get_top_threats(self, n: int = 10) -> List[dict]:
        """Retourne les N IPs les plus dangereuses."""
        return self.get_summary()[:n]

    # ──────────────────────────────────────────────────────────────
    def _cleanup(self, ip: str):
        """Supprime les evenements hors fenetre (appele sous lock)."""
        cutoff = time.time() - self.window_seconds
        window = self._windows[ip]
        while window and window[0].timestamp < cutoff:
            window.popleft()

    # ──────────────────────────────────────────────────────────────
    def _compute_score(self, ip: str) -> dict:
        """Calcule le score depuis la fenetre (appele sous lock)."""
        window = self._windows[ip]

        if not window:
            return {
                "ip":           ip,
                "score":        0.0,
                "level":        "LOW",
                "alert_count":  0,
                "attack_types": [],
                "window_min":   self.window_seconds // 60,
            }

        # Score = somme des points dans la fenetre, normalise sur 100
        raw_score  = sum(e.points for e in window)
        score      = min(100.0, raw_score)

        # Types d'attaques uniques
        attack_types = list({e.threat for e in window})

        # Derniere attaque
        last = window[-1]

        return {
            "ip":            ip,
            "score":         round(score, 1),
            "level":         compute_level(score),
            "alert_count":   len(window),
            "attack_types":  attack_types,
            "last_attack":   last.threat,
            "last_confidence": round(last.confidence, 3),
            "window_min":    self.window_seconds // 60,
        }

    # ──────────────────────────────────────────────────────────────
    def total_tracked(self) -> int:
        return len(self._windows)

    def critical_ips(self) -> List[str]:
        summary = self.get_summary()
        return [s["ip"] for s in summary if s["level"] == "CRITICAL"]


# Singleton global utilise par main.py
risk_engine = RiskScoreEngine()
