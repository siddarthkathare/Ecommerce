"""
Thin inference wrapper around the trained model (ml_model/model.pkl).

Used by app.py / ai_security_analyzer.py to attach a `ml_priority` score
(0=low, 1=medium, 2=urgent) to every Trivy finding, alongside Gemini's
free-text explanation. This is the "AI MODEL" output box feeding into the
rest of the pipeline in the architecture diagram.
"""

import os

import joblib
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(HERE, "model.pkl")

_LABELS = {0: "LOW", 1: "MEDIUM", 2: "URGENT"}

_bundle = None


def _load_bundle():
    global _bundle
    if _bundle is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(
                "No trained model found. Run: python ml_model/train_model.py"
            )
        _bundle = joblib.load(MODEL_PATH)
    return _bundle


def is_model_available():
    return os.path.exists(MODEL_PATH)


def _safe_transform(encoder, value, fallback_index=0):
    try:
        return int(encoder.transform([value])[0])
    except ValueError:
        # Unseen category (e.g. an ecosystem the model never trained on) —
        # fall back to a neutral known value rather than crashing the scan.
        return fallback_index


def predict_priority(
    severity,
    is_secret,
    has_fix_available,
    cve_count,
    ecosystem,
    exposed_to_network=1,
):
    """Return (label:str, confidence:float) for one finding."""

    bundle = _load_bundle()
    model = bundle["model"]
    severity_encoder = bundle["severity_encoder"]
    ecosystem_encoder = bundle["ecosystem_encoder"]

    severity = (severity or "LOW").upper()
    if severity not in severity_encoder.classes_:
        severity = "LOW"

    row = pd.DataFrame(
        [{
            "severity": _safe_transform(severity_encoder, severity),
            "is_secret": int(bool(is_secret)),
            "has_fix_available": int(bool(has_fix_available)),
            "cve_count": int(cve_count or 1),
            "ecosystem": _safe_transform(ecosystem_encoder, (ecosystem or "python").lower()),
            "exposed_to_network": int(bool(exposed_to_network)),
        }],
        columns=bundle["feature_columns"],
    )

    prediction = int(model.predict(row)[0])
    confidence = float(max(model.predict_proba(row)[0]))

    return _LABELS.get(prediction, "LOW"), round(confidence, 3)


def guess_ecosystem(target_or_file):
    """Very rough ecosystem guess from a Trivy 'Target' string / filename,
    used when the pipeline doesn't already know the language."""

    name = (target_or_file or "").lower()
    if "requirements" in name or name.endswith(".py"):
        return "python"
    if "package-lock" in name or "package.json" in name or name.endswith((".js", ".ts")):
        return "node"
    if "pom.xml" in name or "gradle" in name or name.endswith(".java"):
        return "java"
    if "go.mod" in name or "go.sum" in name or name.endswith(".go"):
        return "go"
    return "python"
