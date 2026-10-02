"""
backend/services/ml_service.py
==============================
PURPOSE
-------
Load the trained scikit-learn bundle and score a single email at inference
time. Also exposes the hybrid (rule + ML) combination.

DESIGN NOTES
------------
* The model is OPTIONAL. If ``models/phishing_model.joblib`` does not exist the
  service reports ``available: False`` and the rest of the application keeps
  working with the rule engine alone. The dashboard shows "ML model not
  trained" instead of a fabricated probability.
* The bundle stores the vectoriser, the scaler, the feature-name order and the
  training metadata together, so an inference vector can never silently drift
  from the training vector.
* The model is loaded lazily and cached, so the first request pays the cost and
  subsequent requests are fast.
* A probability is NOT a certainty. Everything returned from here is labelled
  as an estimate, and the UI repeats that.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from backend.config import settings
from backend.services.feature_extractor import FEATURE_NAMES
from backend.utils.logger import app_logger

_LOCK = threading.Lock()
_BUNDLE: Optional[Dict[str, Any]] = None
_LOAD_ATTEMPTED = False
_LOAD_ERROR: Optional[str] = None


def _load_bundle(force: bool = False) -> Optional[Dict[str, Any]]:
    """Load (and cache) the joblib bundle produced by ``ml/train_model.py``."""
    global _BUNDLE, _LOAD_ATTEMPTED, _LOAD_ERROR
    with _LOCK:
        if _BUNDLE is not None and not force:
            return _BUNDLE
        if _LOAD_ATTEMPTED and not force:
            return _BUNDLE
        _LOAD_ATTEMPTED = True
        path = Path(settings.MODEL_PATH)
        if not settings.ML_ENABLED:
            _LOAD_ERROR = "ML is disabled via the ML_ENABLED environment variable."
            return None
        if not path.exists():
            _LOAD_ERROR = (f"Model file not found at {path}. Run 'python ml/train_model.py' "
                           f"(or scripts\\train_model.bat) to train it.")
            app_logger.warning(_LOAD_ERROR)
            return None
        try:
            import joblib
            bundle = joblib.load(path)
            required = {"model", "vectorizer", "feature_names"}
            if not required.issubset(bundle.keys()):
                _LOAD_ERROR = f"Model bundle is missing keys: {required - set(bundle.keys())}"
                app_logger.error(_LOAD_ERROR)
                return None
            _BUNDLE = bundle
            _LOAD_ERROR = None
            app_logger.info("Loaded ML model '%s' from %s", bundle.get("model_name", "?"), path)
            return _BUNDLE
        except Exception as exc:                        # pragma: no cover
            _LOAD_ERROR = f"Failed to load model: {exc}"
            app_logger.error(_LOAD_ERROR)
            return None


def reload_model() -> bool:
    """Force a reload (used after training and by the tests). True when loaded."""
    global _BUNDLE, _LOAD_ATTEMPTED
    with _LOCK:
        _BUNDLE = None
        _LOAD_ATTEMPTED = False
    return _load_bundle(force=True) is not None


def is_available() -> bool:
    """True when a usable model is loaded."""
    return _load_bundle() is not None


def model_info() -> Dict[str, Any]:
    """Metadata about the loaded model for the dashboard / API."""
    bundle = _load_bundle()
    if bundle is None:
        return {
            "available": False,
            "reason": _LOAD_ERROR or "Model not loaded.",
            "model_path": str(settings.MODEL_PATH),
        }
    return {
        "available": True,
        "model_name": bundle.get("model_name", "unknown"),
        "trained_at": bundle.get("trained_at"),
        "dataset_rows": bundle.get("dataset_rows"),
        "test_metrics": bundle.get("test_metrics", {}),
        "validation_metrics": bundle.get("validation_metrics", {}),
        "decision_threshold": bundle.get("decision_threshold", settings.ML_DECISION_THRESHOLD),
        "feature_count": len(bundle.get("feature_names", [])),
        "text_feature_count": bundle.get("text_feature_count"),
        "model_path": str(settings.MODEL_PATH),
        "note": "A probability is an estimate from the training distribution, not a certainty.",
    }


def _build_matrix(ml_text: str, features: Dict[str, Any]):
    """Assemble the same sparse matrix layout that training used."""
    import numpy as np
    from scipy import sparse

    bundle = _BUNDLE
    assert bundle is not None
    vectorizer = bundle["vectorizer"]
    scaler = bundle.get("scaler")
    names: List[str] = bundle["feature_names"]

    x_text = vectorizer.transform([ml_text or ""])
    vector = np.array([[float(features.get(n, 0) or 0) for n in names]], dtype=float)
    if scaler is not None:
        vector = scaler.transform(vector)
        vector = np.clip(vector, 0.0, 1.0)          # MultinomialNB needs non-negative input
    return sparse.hstack([x_text, sparse.csr_matrix(vector)], format="csr")


def predict_email(ml_text: str, features: Dict[str, Any]) -> Dict[str, Any]:
    """Return the ML phishing probability for one email.

    Returns
    -------
    dict with ``available``, and when available:
    ``probability`` (0-1), ``probability_percent``, ``prediction``
    ("PHISHING"/"LEGITIMATE"), ``threshold``, ``model_name``, ``note``.
    """
    bundle = _load_bundle()
    if bundle is None:
        return {
            "available": False,
            "reason": _LOAD_ERROR or "Model not loaded.",
            "probability": None,
            "prediction": None,
        }
    try:
        matrix = _build_matrix(ml_text, features)
        model = bundle["model"]
        threshold = float(bundle.get("decision_threshold", settings.ML_DECISION_THRESHOLD))
        if hasattr(model, "predict_proba"):
            prob = float(model.predict_proba(matrix)[0][1])
        else:                                            # pragma: no cover
            prob = float(model.decision_function(matrix)[0])
            prob = 1.0 / (1.0 + pow(2.718281828, -prob))
        return {
            "available": True,
            "model_name": bundle.get("model_name", "unknown"),
            "probability": round(prob, 4),
            "probability_percent": round(prob * 100, 2),
            "prediction": "PHISHING" if prob >= threshold else "LEGITIMATE",
            "threshold": threshold,
            "trained_at": bundle.get("trained_at"),
            "note": ("This probability is an estimate produced from the synthetic training "
                     "distribution. It is not a certainty and it is not evidence on its own."),
        }
    except Exception as exc:                             # pragma: no cover
        app_logger.error("ML prediction failed: %s", exc)
        return {"available": False, "reason": f"Prediction failed: {exc}",
                "probability": None, "prediction": None}


def hybrid_score(rule_score: int, ml_result: Dict[str, Any],
                 rule_weight: Optional[float] = None,
                 ml_weight: Optional[float] = None) -> Dict[str, Any]:
    """Blend the rule score with the ML probability.

    combined = (rule_weight x rule_score) + (ml_weight x ml_probability x 100)

    WHY COMBINE AT ALL?
    -------------------
    The rule engine is fully interpretable but rigid - it only knows the
    patterns that were programmed. The ML model generalises over wording the
    rules never enumerated, but it cannot explain itself in analyst language.
    Using both means a decision that is explainable AND able to react to
    phrasing the rules missed.

    >>> IMPORTANT <<<
    This project does NOT assume the hybrid is better. ``ml/evaluation.py``
    measures rule-only, ML-only and hybrid on the same held-out test split and
    writes the real numbers into reports/ml_metrics.json. Read those numbers
    before believing any claim about which approach wins.
    """
    rw = settings.HYBRID_RULE_WEIGHT if rule_weight is None else rule_weight
    mw = settings.HYBRID_ML_WEIGHT if ml_weight is None else ml_weight
    total = rw + mw
    if total <= 0:                                        # pragma: no cover
        rw, mw, total = 0.6, 0.4, 1.0
    rw, mw = rw / total, mw / total

    if not ml_result.get("available") or ml_result.get("probability") is None:
        return {
            "available": False,
            "reason": ml_result.get("reason", "ML model unavailable."),
            "combined_score": int(rule_score),
            "rule_score": int(rule_score),
            "ml_probability_percent": None,
            "rule_weight": rw,
            "ml_weight": mw,
            "explanation": ("The ML model is not available, so the hybrid score falls back to "
                            "the rule-based score alone."),
        }

    ml_pct = float(ml_result["probability"]) * 100.0
    combined = rw * float(rule_score) + mw * ml_pct
    combined = max(0.0, min(100.0, combined))
    return {
        "available": True,
        "combined_score": int(round(combined)),
        "rule_score": int(rule_score),
        "ml_probability_percent": round(ml_pct, 2),
        "rule_weight": round(rw, 3),
        "ml_weight": round(mw, 3),
        "model_name": ml_result.get("model_name"),
        "explanation": (
            f"Hybrid = {rw:.2f} x rule({rule_score}) + {mw:.2f} x ML({ml_pct:.1f}%) "
            f"= {combined:.1f}/100. The ML value is a probability estimate, not a certainty, "
            f"and the weights are a project assumption. See reports/ml_metrics.json for the "
            f"measured comparison of rule-only, ML-only and hybrid detection."
        ),
    }
