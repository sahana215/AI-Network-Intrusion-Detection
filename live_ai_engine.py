import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import shutil

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, classification_report

from modules.preprocessing import preprocess_datasets, PROJECT_ROOT
from modules.risk_engine import calculate_composite_risk_score
from modules.attack_classifier import classify_attack_flows
from modules.soc_database import SOCDatabase

MODEL_PATH = PROJECT_ROOT / "models" / "live_hybrid_intrusion_model.pkl"
BACKUP_PATH = PROJECT_ROOT / "models" / "live_hybrid_intrusion_model.pre_ttl_fix.pkl"
ENCODER_PATH = PROJECT_ROOT / "models" / "feature_encoder.pkl"

ATTACK_THRESHOLD = 0.70

EXCLUDED_FEATURES = {
    "sttl": "testbed TTL fingerprint",
    "dttl": "testbed TTL fingerprint",
    "stcpb": "random TCP initial sequence number",
    "dtcpb": "random TCP initial sequence number",
}

FEATURE_COLUMNS = [
    "dur", "proto", "service", "state",
    "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sload", "dload",
    "sinpkt", "dinpkt", "sjit", "djit",
    "swin", "dwin",
    "tcprtt", "synack", "ackdat",
    "smean", "dmean"
]

assert not set(FEATURE_COLUMNS) & set(EXCLUDED_FEATURES), \
    "An excluded feature was added back to FEATURE_COLUMNS."


def _threshold_report(y_true, probabilities):
    y_true = np.asarray(y_true)
    normal_recall = float((probabilities[y_true == 0] < ATTACK_THRESHOLD).mean())
    attack_recall = float((probabilities[y_true == 1] >= ATTACK_THRESHOLD).mean())

    print(f"\nAt attack threshold {ATTACK_THRESHOLD:.2f}:")
    print(f"  Normal recall (1 - false-positive rate): {normal_recall:.4f}")
    print(f"  Attack recall                          : {attack_recall:.4f}")


def train_live_models():
    print("\nLoading UNSW-NB15 dataset...")
    X_train, X_test, y_train, y_test = preprocess_datasets()

    X_train = X_train[FEATURE_COLUMNS].astype(np.float32)
    X_test = X_test[FEATURE_COLUMNS].astype(np.float32)

    print("\nExcluded features (domain-shift shortcuts):")
    for name, reason in EXCLUDED_FEATURES.items():
        print(f"  {name:6s} - {reason}")

    print("\nTraining Live Random Forest...")
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=1
    )
    rf_model.fit(X_train, y_train)

    predictions = rf_model.predict(X_test)
    print(
        "\nRandom Forest Accuracy:",
        round(accuracy_score(y_test, predictions) * 100, 2),
        "%"
    )
    print(classification_report(
        y_test,
        predictions,
        target_names=["Normal", "Attack"],
        zero_division=0
    ))
    _threshold_report(y_test, rf_model.predict_proba(X_test)[:, 1])

    print("\nTraining Live Isolation Forest...")
    normal_traffic = X_train.loc[y_train == 0]
    isolation_model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
        n_jobs=1
    )
    isolation_model.fit(normal_traffic)

    encoder_package = joblib.load(ENCODER_PATH)
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    if MODEL_PATH.exists() and not BACKUP_PATH.exists():
        shutil.copy2(MODEL_PATH, BACKUP_PATH)
        print("\nPrevious model backed up to:", BACKUP_PATH)

    joblib.dump({
        "random_forest": rf_model,
        "isolation_forest": isolation_model,
        "feature_columns": FEATURE_COLUMNS,
        "encoder": encoder_package["encoder"],
        "categorical_columns": encoder_package["categorical_columns"],
        "excluded_features": dict(EXCLUDED_FEATURES),
        "attack_threshold": ATTACK_THRESHOLD,
        "trained_at": datetime.now(timezone.utc).isoformat()
    }, MODEL_PATH)

    print("\n================================")
    print("LIVE AI MODEL TRAINING COMPLETE")
    print("Features:", len(FEATURE_COLUMNS))
    print("Saved:", MODEL_PATH)
    print("================================")


def load_live_models():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Live AI model not found at {MODEL_PATH}. Run: python -m modules.live_ai_engine"
        )
    return joblib.load(MODEL_PATH)


def calculate_live_risk(probability):
    if probability >= 0.90:
        return "CRITICAL"
    if probability >= ATTACK_THRESHOLD:
        return "HIGH"
    if probability >= 0.50:
        return "MEDIUM"
    return "LOW"


class AlertDeduplicator:
    """Tracks flow alert timestamps to prevent alert flooding for ongoing flows.

    A flow ID that has already triggered an alert will not re-trigger another alert
    until cooldown_seconds have elapsed. Genuinely new flow IDs alert immediately.
    """

    def __init__(self, cooldown_seconds=60.0):
        self.cooldown_seconds = float(cooldown_seconds)
        self.last_alert_times = {}

    def should_alert(self, flow_id, current_time=None):
        now = float(current_time) if current_time is not None else time.time()
        last_time = self.last_alert_times.get(str(flow_id), 0.0)
        if now - last_time >= self.cooldown_seconds:
            self.last_alert_times[str(flow_id)] = now
            if len(self.last_alert_times) > 5000:
                self._purge(now)
            return True
        return False

    def _purge(self, now):
        cutoff = now - (self.cooldown_seconds * 2)
        expired = [fid for fid, t in self.last_alert_times.items() if t < cutoff]
        for fid in expired:
            del self.last_alert_times[fid]

    def reset(self):
        self.last_alert_times.clear()


_ALERT_DEDUPLICATOR = AlertDeduplicator(cooldown_seconds=60.0)


def detect_live_flows(flow_data, auto_alert=False, alert_cooldown=60.0, deduplicator=None):
    """Executes live threat detection using Random Forest, Isolation Forest,

    Multiclass Attack Classification, and Multi-factor Risk Scoring with alert deduplication.
    """
    if flow_data is None or len(flow_data) == 0:
        return None

    active_dedup = deduplicator if deduplicator is not None else _ALERT_DEDUPLICATOR
    if alert_cooldown != active_dedup.cooldown_seconds:
        active_dedup.cooldown_seconds = float(alert_cooldown)

    package = load_live_models()
    rf_model = package["random_forest"]
    isolation_model = package["isolation_forest"]
    feature_columns = package["feature_columns"]
    encoder = package["encoder"]
    categorical_columns = package["categorical_columns"]

    data = flow_data.copy()

    for column in feature_columns:
        if column not in data.columns:
            data[column] = 0

    for column in categorical_columns:
        if column in data.columns:
            data[column] = data[column].fillna("-").astype(str)

    available_categorical = [c for c in categorical_columns if c in feature_columns]
    if available_categorical:
        data[available_categorical] = encoder.transform(data[available_categorical])

    features = data[feature_columns].replace([np.inf, -np.inf], 0).fillna(0).astype(np.float32)

    probabilities = rf_model.predict_proba(features)[:, 1]
    isolation_predictions = isolation_model.predict(features)

    # Classify attack categories
    try:
        category_df = classify_attack_flows(flow_data)
    except Exception:
        category_df = pd.DataFrame()

    results = []
    soc_db = SOCDatabase() if auto_alert else None

    for index in range(len(features)):
        probability = float(probabilities[index])
        is_attack = probability >= ATTACK_THRESHOLD
        is_anomaly = int(isolation_predictions[index]) == -1

        # Multi-class attack category
        if not category_df.empty and index < len(category_df):
            attk_cat = category_df.iloc[index].get("Attack_Category", "Normal" if not is_attack else "Generic")
        else:
            attk_cat = "Normal" if not is_attack else "Suspicious Activity"

        src_ip = str(data.iloc[index].get("Source IP", "Unknown"))
        dst_ip = str(data.iloc[index].get("Destination IP", "Unknown"))
        src_port = int(data.iloc[index].get("Source Port", 0))
        dst_port = int(data.iloc[index].get("Destination Port", 0))
        proto = str(data.iloc[index].get("Protocol", "TCP"))
        flow_id = str(data.iloc[index].get("Flow ID", f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"))
        rate_val = float(data.iloc[index].get("rate", 0.0))

        # Composite multi-factor risk score
        risk_score, risk_level, _ = calculate_composite_risk_score(
            attack_probability=probability,
            is_anomaly=is_anomaly,
            attack_category=attk_cat,
            dest_port=dst_port,
            packet_rate=rate_val
        )

        if is_attack and is_anomaly:
            reason = f"Random Forest detected {attk_cat} signature; Isolation Forest confirmed statistical anomaly"
        elif is_attack:
            reason = f"Random Forest detected {attk_cat} signature above threshold ({probability * 100:.1f}%)"
        elif is_anomaly:
            reason = "Unusual traffic distribution flagged by Isolation Forest; attack pattern unconfirmed"
        else:
            reason = "Traffic pattern verified within normal operating boundaries"

        # Auto-generate security alert for SOC tracking if attack or high/critical (with flow deduplication)
        if auto_alert and soc_db and (is_attack or risk_level in ("HIGH", "CRITICAL")):
            if active_dedup.should_alert(flow_id):
                soc_db.create_alert(
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol=proto,
                    attack_category=attk_cat,
                    severity=risk_level,
                    risk_score=risk_score,
                    confidence=round(probability * 100, 2),
                    detection_reason=reason,
                    evidence={"flow_id": flow_id, "anomaly": is_anomaly, "probability": probability}
                )

        results.append({
            "Flow ID": flow_id,
            "Source IP": src_ip,
            "Destination IP": dst_ip,
            "Source Port": src_port,
            "Destination Port": dst_port,
            "Protocol": proto,
            "Random_Forest": "Attack" if is_attack else "Normal",
            "Anomaly_Detection": "Anomaly" if is_anomaly else "Normal",
            "Final_Result": "Attack" if is_attack else "Normal",
            "Attack_Category": attk_cat,
            "Attack_Probability": round(probability * 100, 2),
            "Risk_Score": risk_score,
            "Risk_Level": risk_level,
            "Detection_Reason": reason
        })

    return pd.DataFrame(results)


if __name__ == "__main__":
    train_live_models()
