"""
tests/test_predictor.py
Tests unitaires de predictor.py — logique ML pure, sans HTTP.

Lancer :
    cd ~/onos_open/ids_service
    pytest tests/test_predictor.py -v
"""
import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from predictor import IDSPredictor, decide_action, N_FEATURES, KNOWN_CLASSES

MODEL_DIR = Path(__file__).parent.parent / "models"


# ── Fixture : predictor charge une seule fois pour tous les tests ──
@pytest.fixture(scope="module")
def p():
    pred = IDSPredictor()
    pred.load(MODEL_DIR)
    return pred


# ════════════════════════════════════════════════════════════════════
# 1. Chargement
# ════════════════════════════════════════════════════════════════════
class TestChargement:

    def test_is_loaded_apres_load(self, p):
        assert p.is_loaded is True

    def test_nombre_features_correct(self, p):
        assert p.model.n_features_in_ == N_FEATURES

    def test_14_classes_presentes(self, p):
        assert len(p.label_encoder.classes_) == 14

    def test_toutes_classes_connues(self, p):
        classes = list(p.label_encoder.classes_)
        for c in KNOWN_CLASSES:
            assert c in classes

    def test_erreur_sans_load(self):
        """predict_one() doit lever RuntimeError si load() n'a pas ete appele."""
        vide = IDSPredictor()
        with pytest.raises(RuntimeError):
            vide.predict_one([0.0] * N_FEATURES)


# ════════════════════════════════════════════════════════════════════
# 2. predict_one() — cas nominaux
# ════════════════════════════════════════════════════════════════════
class TestPredictOne:

    def test_retourne_4_champs(self, p):
        r = p.predict_one([0.5] * N_FEATURES)
        assert "threat"     in r
        assert "confidence" in r
        assert "action"     in r
        assert "latency_ms" in r

    def test_threat_est_une_classe_connue(self, p):
        r = p.predict_one([0.5] * N_FEATURES)
        assert r["threat"] in KNOWN_CLASSES

    def test_confidence_entre_0_et_1(self, p):
        r = p.predict_one([0.5] * N_FEATURES)
        assert 0.0 <= r["confidence"] <= 1.0

    def test_action_valide(self, p):
        r = p.predict_one([0.5] * N_FEATURES)
        assert r["action"] in ("BLOCK", "INSPECT", "ALLOW")

    def test_latency_positive(self, p):
        r = p.predict_one([0.5] * N_FEATURES)
        assert r["latency_ms"] > 0

    def test_deterministe(self, p):
        """Memes features -> meme resultat."""
        features = [1.0, 0.0, 500.0] + [0.3] * 79
        r1 = p.predict_one(features)
        r2 = p.predict_one(features)
        assert r1["threat"]     == r2["threat"]
        assert r1["confidence"] == r2["confidence"]
        assert r1["action"]     == r2["action"]


# ════════════════════════════════════════════════════════════════════
# 3. predict_one() — cas d'erreur et cas limites
# ════════════════════════════════════════════════════════════════════
class TestPredictOneErreurs:

    def test_81_features_leve_valueerror(self, p):
        with pytest.raises(ValueError, match="Expected 82"):
            p.predict_one([0.5] * 81)

    def test_83_features_leve_valueerror(self, p):
        with pytest.raises(ValueError):
            p.predict_one([0.5] * 83)

    def test_features_vides_leve_valueerror(self, p):
        with pytest.raises(ValueError):
            p.predict_one([])

    def test_nan_ne_plante_pas(self, p):
        """NaN remplaces par 0 — pas de crash."""
        r = p.predict_one([float("nan")] * N_FEATURES)
        assert r["threat"] in KNOWN_CLASSES

    def test_inf_ne_plante_pas(self, p):
        """Inf remplaces par 0 — pas de crash."""
        r = p.predict_one([float("inf")] * N_FEATURES)
        assert r["threat"] in KNOWN_CLASSES

    def test_tout_zero(self, p):
        r = p.predict_one([0.0] * N_FEATURES)
        assert r["threat"] in KNOWN_CLASSES

    def test_grandes_valeurs(self, p):
        r = p.predict_one([1e9] * N_FEATURES)
        assert r["threat"] in KNOWN_CLASSES

    def test_valeurs_negatives(self, p):
        r = p.predict_one([-100.0] * N_FEATURES)
        assert r["threat"] in KNOWN_CLASSES


# ════════════════════════════════════════════════════════════════════
# 4. predict_batch()
# ════════════════════════════════════════════════════════════════════
class TestPredictBatch:

    def test_batch_5_retourne_5_resultats(self, p):
        results = p.predict_batch([[0.5] * N_FEATURES for _ in range(5)])
        assert len(results) == 5

    def test_batch_1_flux(self, p):
        results = p.predict_batch([[0.5] * N_FEATURES])
        assert len(results) == 1

    def test_batch_100_flux(self, p):
        results = p.predict_batch([[float(i % 5) * 0.1] * N_FEATURES for i in range(100)])
        assert len(results) == 100

    def test_chaque_resultat_a_les_champs(self, p):
        results = p.predict_batch([[0.5] * N_FEATURES for _ in range(3)])
        for r in results:
            assert "threat"     in r
            assert "confidence" in r
            assert "action"     in r
            assert "flow_index" in r

    def test_flow_index_correct(self, p):
        results = p.predict_batch([[0.5] * N_FEATURES for _ in range(4)])
        for i, r in enumerate(results):
            assert r["flow_index"] == i

    def test_mauvaise_taille_leve_valueerror(self, p):
        with pytest.raises(ValueError):
            p.predict_batch([[0.5] * N_FEATURES, [0.5] * 80])


# ════════════════════════════════════════════════════════════════════
# 5. decide_action() — regle metier
# ════════════════════════════════════════════════════════════════════
class TestDecideAction:

    def test_benign_toujours_allow(self):
        assert decide_action("BENIGN", 0.99) == "ALLOW"
        assert decide_action("BENIGN", 0.50) == "ALLOW"
        assert decide_action("BENIGN", 0.10) == "ALLOW"

    def test_haute_confiance_block(self):
        assert decide_action("SYN_FLOOD", 0.95) == "BLOCK"
        assert decide_action("DDOS",      0.85) == "BLOCK"
        assert decide_action("XSS",       1.00) == "BLOCK"

    def test_confiance_moyenne_inspect(self):
        assert decide_action("SYN_FLOOD", 0.80) == "INSPECT"
        assert decide_action("PORT_SCAN", 0.60) == "INSPECT"

    def test_confiance_faible_allow(self):
        assert decide_action("DDOS",      0.50) == "ALLOW"
        assert decide_action("SYN_FLOOD", 0.30) == "ALLOW"

    def test_exactement_seuil_085_block(self):
        assert decide_action("MAC_FLOODING", 0.85) == "BLOCK"

    def test_juste_sous_seuil_inspect(self):
        assert decide_action("MAC_FLOODING", 0.849) == "INSPECT"


# ════════════════════════════════════════════════════════════════════
# 6. Statistiques internes
# ════════════════════════════════════════════════════════════════════
class TestStats:

    def test_predict_count_incremente(self, p):
        avant = p.stats()["predict_count"]
        p.predict_one([0.5] * N_FEATURES)
        assert p.stats()["predict_count"] == avant + 1

    def test_avg_latency_positive(self, p):
        p.predict_one([0.5] * N_FEATURES)
        assert p.stats()["avg_latency_ms"] > 0

    def test_model_loaded_true(self, p):
        assert p.stats()["model_loaded"] is True

    def test_uptime_positif(self, p):
        assert p.stats()["uptime_s"] >= 0
