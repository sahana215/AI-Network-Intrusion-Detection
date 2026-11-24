import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score

from modules.preprocessing import preprocess_datasets

CLASSIFIER_PATH = PROJECT_ROOT / "models" / "attack_classifier_model.pkl"
ENCODER_PATH = PROJECT_ROOT / "models" / "feature_encoder.pkl"

# Core flow features aligned with live flow extraction
CLASSIFIER_FEATURES = [
    "dur", "proto", "service", "state",
    "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sload", "dload",
    "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "dwin",
    "tcprtt", "synack", "ackdat",
    "smean", "dmean"
]

# Attack severity mapping for risk scoring & SOC prioritization
ATTACK_SEVERITY_MAP = {
    "Normal": "LOW",
    "Generic": "MEDIUM",
    "Fuzzers": "MEDIUM",
    "Analysis": "MEDIUM",
    "Reconnaissance": "HIGH",
    "Port Scanning": "HIGH",
    "Exploits": "HIGH",
    "DoS": "HIGH",
    "DDoS": "CRITICAL",
    "Backdoor": "CRITICAL",
    "Shellcode": "CRITICAL",
    "Worms": "CRITICAL",
}


def train_attack_classifier():
    """Trains a multi-class Random Forest attack classifier on UNSW-NB15 attack_cat.

    Evaluates on held-out testing dataset and saves model to models/attack_classifier_model.pkl.
    """
    print("\n[ATTACK CLASSIFIER] Loading preprocessed datasets...")
    X_train, X_test, y_train, y_test, y_train_cat, y_test_cat = preprocess_datasets(include_attack_cat=True)

    X_train_sub = X_train[CLASSIFIER_FEATURES].astype(np.float32)
    X_test_sub = X_test[CLASSIFIER_FEATURES].astype(np.float32)

    print(f"[ATTACK CLASSIFIER] Training samples: {len(X_train_sub):,}, Features: {len(CLASSIFIER_FEATURES)}")
    print(f"[ATTACK CLASSIFIER] Target classes: {sorted(y_train_cat.unique())}")

    classifier = RandomForestClassifier(
        n_estimators=100,
        max_depth=22,
        min_samples_split=6,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    print("[ATTACK CLASSIFIER] Training Multi-class Random Forest...")
    classifier.fit(X_train_sub, y_train_cat)

    predictions = classifier.predict(X_test_sub)
    acc = accuracy_score(y_test_cat, predictions)
    macro_f1 = f1_score(y_test_cat, predictions, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_test_cat, predictions, average="weighted", zero_division=0)

    print(f"\n[ATTACK CLASSIFIER RESULTS]")
    print(f"Overall Accuracy: {acc * 100:.2f}%")
    print(f"Macro F1 Score  : {macro_f1 * 100:.2f}%")
    print(f"Weighted F1     : {weighted_f1 * 100:.2f}%")
    print("\nDetailed Classification Report:")
    print(classification_report(y_test_cat, predictions, zero_division=0))

    encoder_pkg = joblib.load(ENCODER_PATH)

    CLASSIFIER_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({
        "classifier": classifier,
        "classes": classifier.classes_.tolist(),
        "feature_columns": CLASSIFIER_FEATURES,
        "encoder": encoder_pkg["encoder"],
        "categorical_columns": encoder_pkg["categorical_columns"],
        "accuracy": acc,
        "weighted_f1": weighted_f1,
    }, CLASSIFIER_PATH)

    print(f"[ATTACK CLASSIFIER] Model successfully saved to: {CLASSIFIER_PATH}")
    return classifier


def load_attack_classifier():
    """Loads trained multi-class attack classifier package."""
    if not CLASSIFIER_PATH.exists():
        train_attack_classifier()

    return joblib.load(CLASSIFIER_PATH)


def classify_attack_flows(flow_data):
    """Predicts specific attack classes (e.g. DoS, Exploits, Fuzzers, Reconnaissance, Normal)

    for given network flow records.
    Returns:
        DataFrame with ['Predicted_Class', 'Class_Confidence', 'Class_Severity']
    """
    if flow_data is None or len(flow_data) == 0:
        return pd.DataFrame()

    pkg = load_attack_classifier()
    model = pkg["classifier"]
    feature_columns = pkg["feature_columns"]
    encoder = pkg["encoder"]
    categorical_columns = pkg["categorical_columns"]

    data = flow_data.copy()

    for col in feature_columns:
        if col not in data.columns:
            data[col] = 0

    for col in categorical_columns:
        if col in data.columns:
            data[col] = data[col].fillna("-").astype(str)

    available_cat = [c for c in categorical_columns if c in feature_columns]
    if available_cat:
        data[available_cat] = encoder.transform(data[available_cat])

    X = data[feature_columns].replace([np.inf, -np.inf], 0).fillna(0).astype(np.float32)

    predictions = model.predict(X)
    probabilities = model.predict_proba(X)
    max_probs = np.max(probabilities, axis=1)

    results = []
    for pred, prob in zip(predictions, max_probs):
        severity = ATTACK_SEVERITY_MAP.get(pred, "MEDIUM" if pred != "Normal" else "LOW")
        results.append({
            "Attack_Category": pred,
            "Category_Confidence": round(float(prob) * 100, 2),
            "Category_Severity": severity
        })

    return pd.DataFrame(results)


if __name__ == "__main__":
    train_attack_classifier()
