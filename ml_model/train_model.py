"""
Dataset-Driven Learning
------------------------
Maps to the "DATASET-DRIVEN LEARNING" box in the architecture diagram:

    VULNERABILITY DATA -> DATA PROCESSING -> MODEL TRAINING -> AI MODEL

This trains a small RandomForest classifier that predicts a `priority_label`
(0 = low, 1 = medium, 2 = urgent) for a vulnerability finding, using features
that are cheap to derive from any Trivy report:

    severity, is_secret, has_fix_available, cve_count, ecosystem, exposed_to_network

This model is DIFFERENT from the Gemini generative-AI analysis. Gemini reads
free-text source code + the report and explains/suggests fixes ("AI-BASED
ANALYSIS" box). This model instead learns numeric patterns from historical
scan outcomes to produce a fast, offline priority score that doesn't depend
on an external API being available or paid for. The two signals are combined
in app.py.

Run:
    python ml_model/train_model.py

Produces:
    ml_model/model.pkl        (trained classifier + encoders, via joblib)
    ml_model/metrics.json     (train/test accuracy for the report/README)

The FEEDBACK LOOP is closed by feedback/retrain.py, which appends newly
observed scan outcomes to this same dataset and re-runs this training step.
"""

import json
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

HERE = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(HERE, "dataset", "vulnerability_dataset.csv")
FEEDBACK_PATH = os.path.join(
    os.path.dirname(HERE), "feedback", "feedback_log.csv"
)
MODEL_PATH = os.path.join(HERE, "model.pkl")
METRICS_PATH = os.path.join(HERE, "metrics.json")

FEATURE_COLUMNS = [
    "severity",
    "is_secret",
    "has_fix_available",
    "cve_count",
    "ecosystem",
    "exposed_to_network",
]
LABEL_COLUMN = "priority_label"
SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def load_training_data():
    """DATA PROCESSING: load the base dataset and merge in anything the
    feedback loop has logged from real scans since the last training run."""

    frames = [pd.read_csv(DATASET_PATH)]

    if os.path.exists(FEEDBACK_PATH) and os.path.getsize(FEEDBACK_PATH) > 0:
        feedback_df = pd.read_csv(FEEDBACK_PATH)
        # Only keep feedback rows that have all required columns filled in.
        feedback_df = feedback_df.dropna(
            subset=FEATURE_COLUMNS + [LABEL_COLUMN]
        )
        if not feedback_df.empty:
            frames.append(feedback_df[FEATURE_COLUMNS + [LABEL_COLUMN]])
            print(
                f"Merged {len(feedback_df)} feedback rows collected from "
                f"real pipeline runs into the training set."
            )

    data = pd.concat(frames, ignore_index=True)
    data = data.drop_duplicates()
    return data


def build_features(data: pd.DataFrame):
    severity_encoder = LabelEncoder()
    severity_encoder.fit(SEVERITY_ORDER)

    ecosystem_encoder = LabelEncoder()
    ecosystem_encoder.fit(sorted(data["ecosystem"].unique()))

    features = pd.DataFrame(
        {
            "severity": severity_encoder.transform(data["severity"]),
            "is_secret": data["is_secret"].astype(int),
            "has_fix_available": data["has_fix_available"].astype(int),
            "cve_count": data["cve_count"].astype(int),
            "ecosystem": ecosystem_encoder.transform(data["ecosystem"]),
            "exposed_to_network": data["exposed_to_network"].astype(int),
        }
    )

    return features, severity_encoder, ecosystem_encoder


def train():
    data = load_training_data()
    features, severity_encoder, ecosystem_encoder = build_features(data)
    labels = data[LABEL_COLUMN].astype(int)

    x_train, x_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, random_state=42, stratify=labels
    )

    model = RandomForestClassifier(
        n_estimators=200, max_depth=6, random_state=42
    )
    model.fit(x_train, y_train)

    train_accuracy = accuracy_score(y_train, model.predict(x_train))
    test_accuracy = accuracy_score(y_test, model.predict(x_test))

    joblib.dump(
        {
            "model": model,
            "severity_encoder": severity_encoder,
            "ecosystem_encoder": ecosystem_encoder,
            "feature_columns": FEATURE_COLUMNS,
        },
        MODEL_PATH,
    )

    metrics = {
        "rows_used": int(len(data)),
        "train_accuracy": round(float(train_accuracy), 4),
        "test_accuracy": round(float(test_accuracy), 4),
        "feature_importances": {
            col: round(float(imp), 4)
            for col, imp in zip(FEATURE_COLUMNS, model.feature_importances_)
        },
    }

    with open(METRICS_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print("Model trained and saved to", MODEL_PATH)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    train()
