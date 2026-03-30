"""
tests/test_api.py
Tests unitaires des endpoints HTTP (main.py).
Utilise TestClient — pas besoin de demarrer un vrai serveur.

Lancer :
    cd ~/onos_open/ids_service
    pytest tests/test_api.py -v

Tout d'un coup :
    pytest tests/ -v
"""
import sys, time
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient
from main import app
from predictor import predictor, N_FEATURES

MODEL_DIR = Path(__file__).parent.parent / "models"


# ── Charge les modeles une seule fois pour tout le fichier ────────
@pytest.fixture(scope="module", autouse=True)
def charger_modeles():
    if not predictor.is_loaded:
        predictor.load(MODEL_DIR)
    yield


# ── Client HTTP in-process (pas de vrai serveur) ─────────────────
@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


# ── Helpers pour generer des payloads ────────────────────────────
def payload_ok(flow_id="flow-test", valeur=0.5):
    """Payload valide avec N_FEATURES features."""
    return {"flow_id": flow_id, "features": [valeur] * N_FEATURES}

def payload_batch(n=5):
    """Batch de n flux valides."""
    return {
        "flows": [
            {"flow_id": f"f{i}", "features": [float(i % 5) * 0.1] * N_FEATURES}
            for i in range(n)
        ]
    }


# ════════════════════════════════════════════════════════════════════
# 1. GET /health
# ════════════════════════════════════════════════════════════════════
class TestHealth:

    def test_retourne_200(self, client):
        r = client.get("/health")
        assert r.status_code == 200

    def test_status_ok(self, client):
        assert client.get("/health").json()["status"] == "ok"

    def test_model_loaded_true(self, client):
        assert client.get("/health").json()["model_loaded"] is True

    def test_n_features_correct(self, client):
        assert client.get("/health").json()["n_features"] == N_FEATURES

    def test_n_classes_correct(self, client):
        assert client.get("/health").json()["n_classes"] == 14

    def test_version_presente(self, client):
        assert "version" in client.get("/health").json()


# ════════════════════════════════════════════════════════════════════
# 2. POST /predict — cas nominaux
# ════════════════════════════════════════════════════════════════════
class TestPredictNominal:

    def test_retourne_200(self, client):
        assert client.post("/predict", json=payload_ok()).status_code == 200

    def test_champ_threat(self, client):
        assert "threat" in client.post("/predict", json=payload_ok()).json()

    def test_champ_confidence(self, client):
        assert "confidence" in client.post("/predict", json=payload_ok()).json()

    def test_champ_action(self, client):
        assert "action" in client.post("/predict", json=payload_ok()).json()

    def test_champ_latency(self, client):
        assert "latency_ms" in client.post("/predict", json=payload_ok()).json()

    def test_flow_id_renvoye(self, client):
        r = client.post("/predict", json=payload_ok("mon-flux-abc"))
        assert r.json()["flow_id"] == "mon-flux-abc"

    def test_confidence_entre_0_et_1(self, client):
        c = client.post("/predict", json=payload_ok()).json()["confidence"]
        assert 0.0 <= c <= 1.0

    def test_action_valide(self, client):
        a = client.post("/predict", json=payload_ok()).json()["action"]
        assert a in ("BLOCK", "INSPECT", "ALLOW")

    def test_threat_classe_connue(self, client):
        classes = {
            "ARP_SPOOFING", "BENIGN", "DDOS", "DHCP_SPOOFING", "IP_SPOOFING",
            "MAC_FLOODING", "PORT_SCAN", "ROUTING_ATTACK", "SESSION_HIJACKING",
            "SQL_INJECTION", "SSL_STRIPPING", "STP_SPOOFING", "SYN_FLOOD", "XSS",
        }
        assert client.post("/predict", json=payload_ok()).json()["threat"] in classes

    def test_deterministe(self, client):
        """Deux requetes identiques -> meme reponse."""
        p = payload_ok("det", 0.3)
        r1 = client.post("/predict", json=p).json()
        r2 = client.post("/predict", json=p).json()
        assert r1["threat"]     == r2["threat"]
        assert r1["confidence"] == r2["confidence"]
        assert r1["action"]     == r2["action"]


# ════════════════════════════════════════════════════════════════════
# 3. POST /predict — cas d'erreur
# ════════════════════════════════════════════════════════════════════
class TestPredictErreurs:

    def test_81_features_retourne_422(self, client):
        r = client.post("/predict", json={"flow_id": "x", "features": [0.5] * 81})
        assert r.status_code == 422

    def test_83_features_retourne_422(self, client):
        r = client.post("/predict", json={"flow_id": "x", "features": [0.5] * 83})
        assert r.status_code == 422

    def test_features_vides_retourne_422(self, client):
        r = client.post("/predict", json={"flow_id": "x", "features": []})
        assert r.status_code == 422

    def test_flow_id_manquant_retourne_422(self, client):
        r = client.post("/predict", json={"features": [0.5] * N_FEATURES})
        assert r.status_code == 422

    def test_features_manquantes_retourne_422(self, client):
        r = client.post("/predict", json={"flow_id": "x"})
        assert r.status_code == 422

    def test_body_vide_retourne_422(self, client):
        r = client.post("/predict", json={})
        assert r.status_code == 422

    def test_features_string_retourne_422(self, client):
        r = client.post("/predict", json={"flow_id": "x", "features": ["abc"] * N_FEATURES})
        assert r.status_code == 422

    def test_jamais_500_sur_input_invalide(self, client):
        """Un input invalide doit retourner 422, jamais 500 (crash serveur)."""
        r = client.post("/predict", json={"flow_id": "x", "features": [0.5] * 81})
        assert r.status_code != 500


# ════════════════════════════════════════════════════════════════════
# 4. POST /predict/batch
# ════════════════════════════════════════════════════════════════════
class TestBatch:

    def test_retourne_200(self, client):
        assert client.post("/predict/batch", json=payload_batch(5)).status_code == 200

    def test_total_flows_correct(self, client):
        r = client.post("/predict/batch", json=payload_batch(8))
        assert r.json()["total_flows"] == 8

    def test_results_est_une_liste(self, client):
        r = client.post("/predict/batch", json=payload_batch(3))
        assert isinstance(r.json()["results"], list)
        assert len(r.json()["results"]) == 3

    def test_chaque_resultat_a_les_champs(self, client):
        r = client.post("/predict/batch", json=payload_batch(3))
        for res in r.json()["results"]:
            assert "threat"     in res
            assert "confidence" in res
            assert "action"     in res
            assert "flow_id"    in res

    def test_flow_ids_preserves(self, client):
        r = client.post("/predict/batch", json=payload_batch(3))
        for i, res in enumerate(r.json()["results"]):
            assert res["flow_id"] == f"f{i}"

    def test_batch_time_present(self, client):
        r = client.post("/predict/batch", json=payload_batch(5))
        assert r.json()["batch_time_ms"] > 0

    def test_batch_vide_retourne_422(self, client):
        r = client.post("/predict/batch", json={"flows": []})
        assert r.status_code == 422

    def test_flux_mauvaise_taille_retourne_422(self, client):
        p = {
            "flows": [
                {"flow_id": "ok",  "features": [0.5] * N_FEATURES},
                {"flow_id": "bad", "features": [0.5] * 80},
            ]
        }
        assert client.post("/predict/batch", json=p).status_code == 422

    def test_batch_50_flux(self, client):
        r = client.post("/predict/batch", json=payload_batch(50))
        assert r.status_code == 200
        assert r.json()["total_flows"] == 50


# ════════════════════════════════════════════════════════════════════
# 5. GET /metrics
# ════════════════════════════════════════════════════════════════════
class TestMetrics:

    def test_retourne_200(self, client):
        assert client.get("/metrics").status_code == 200

    def test_predict_count_present(self, client):
        assert "predict_count" in client.get("/metrics").json()

    def test_avg_latency_present(self, client):
        assert "avg_latency_ms" in client.get("/metrics").json()

    def test_model_loaded_true(self, client):
        assert client.get("/metrics").json()["model_loaded"] is True

    def test_predict_count_augmente(self, client):
        avant = client.get("/metrics").json()["predict_count"]
        client.post("/predict", json=payload_ok())
        apres = client.get("/metrics").json()["predict_count"]
        assert apres > avant


# ════════════════════════════════════════════════════════════════════
# 6. Performance
# ════════════════════════════════════════════════════════════════════
class TestPerformance:

    def test_latency_ms_positive(self, client):
        r = client.post("/predict", json=payload_ok())
        assert r.json()["latency_ms"] > 0

    def test_100_requetes_sans_echec(self, client):
        """100 requetes consecutives — aucune ne doit echouer."""
        echecs = 0
        for i in range(100):
            r = client.post("/predict", json=payload_ok(f"perf-{i}"))
            if r.status_code != 200:
                echecs += 1
        assert echecs == 0, f"{echecs}/100 requetes ont echoue"

    def test_batch_plus_rapide_que_sequentiel(self, client):
        """Un batch de 30 flux doit etre plus rapide que 30 requetes separees."""
        t0 = time.perf_counter()
        for i in range(30):
            client.post("/predict", json=payload_ok(f"seq-{i}"))
        t_seq = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        client.post("/predict/batch", json=payload_batch(30))
        t_batch = (time.perf_counter() - t0) * 1000

        assert t_batch < t_seq, (
            f"Batch ({t_batch:.0f}ms) devrait etre plus rapide "
            f"que sequentiel ({t_seq:.0f}ms)"
        )
