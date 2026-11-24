import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import pandas as pd
import numpy as np

from modules.preprocessing import preprocess_datasets, PROJECT_ROOT
from modules.risk_engine import calculate_composite_risk_score
from modules.attack_classifier import classify_attack_flows

MODEL_PATH = PROJECT_ROOT / "models" / "hybrid_intrusion_model.pkl"
REPORT_DIR = PROJECT_ROOT / "reports"
REPORT_DIR.mkdir(exist_ok=True)


def load_models():
    """Loads offline trained hybrid Random Forest and Isolation Forest models."""
    if not MODEL_PATH.exists():
        raise FileNotFoundError(f"Trained model not found at: {MODEL_PATH}")

    package = joblib.load(MODEL_PATH)
    return (
        package["random_forest"],
        package["isolation_forest"],
        package["feature_columns"],
        package["encoder"],
        package["categorical_columns"]
    )


def preprocess_live_traffic(data):
    """Aligns arbitrary flow dataframe to model feature columns and applies encoding."""
    rf_model, isolation_model, feature_columns, encoder, categorical_columns = load_models()
    data = data.copy()

    for column in feature_columns:
        if column not in data.columns:
            data[column] = 0

    available_categorical = [col for col in categorical_columns if col in data.columns]
    if available_categorical:
        for col in available_categorical:
            data[col] = data[col].fillna("-").astype(str)
        data[available_categorical] = encoder.transform(data[available_categorical])

    return data[feature_columns]


def calculate_risk(probability, anomaly):
    """Legacy 4-tier risk level calculator for backwards compatibility."""
    if probability >= 0.90 and anomaly:
        return "CRITICAL"
    elif probability >= 0.75 or anomaly:
        return "HIGH"
    elif probability >= 0.50:
        return "MEDIUM"
    return "LOW"


def detect_network_traffic(data, log_to_soc=False):
    """Executes high-performance hybrid detection (Random Forest + Isolation Forest + Multiclass Attack Classifier)
    on batch network records with multi-factor risk scoring.
    """
    rf_model, isolation_model, feature_columns, encoder, categorical_columns = load_models()

    raw_data = data.copy()
    processed = data.copy()

    for col in feature_columns:
        if col not in processed.columns:
            processed[col] = 0

    available_categorical = [col for col in categorical_columns if col in processed.columns]
    if available_categorical:
        for col in available_categorical:
            processed[col] = processed[col].fillna("-").astype(str)
        processed[available_categorical] = encoder.transform(processed[available_categorical])

    processed_features = processed.reindex(columns=feature_columns, fill_value=0).astype(np.float32)

    rf_predictions = rf_model.predict(processed_features)
    rf_probabilities = rf_model.predict_proba(processed_features)[:, 1]
    isolation_results = isolation_model.predict(processed_features)

    # Classify attack categories using multiclass classifier
    try:
        category_df = classify_attack_flows(raw_data)
        if not category_df.empty and "Attack_Category" in category_df.columns:
            attk_cats = category_df["Attack_Category"].values
        else:
            attk_cats = np.where(rf_predictions == 1, "Generic", "Normal")
    except Exception:
        attk_cats = np.where(rf_predictions == 1, "Generic", "Normal")

    is_attack = (rf_predictions == 1)
    is_anomaly = (isolation_results == -1)
    hybrid_result = is_attack | is_anomaly

    prob_pts = rf_probabilities * 45.0
    anom_pts = np.where(is_anomaly, 15.0, 0.0)
    cat_pts = np.where(is_attack, 10.0, 0.0)
    scores = np.clip(np.round(prob_pts + anom_pts + cat_pts), 0, 100).astype(int)
    risk_lvls = np.where(
        scores >= 80, "CRITICAL",
        np.where(scores >= 60, "HIGH",
                 np.where(scores >= 35, "MEDIUM", "LOW"))
    )

    reasons = [
        f"Confirmed Attack ({cat}) with anomaly pattern" if attk and anom else (
            f"Random Forest identified {cat} signature" if attk else (
                "Isolation Forest flagged anomalous distribution" if anom else
                "Communication verified within normal behavioral bounds"
            )
        )
        for attk, anom, cat in zip(is_attack, is_anomaly, attk_cats)
    ]

    total_len = len(processed_features)
    return pd.DataFrame({
        "Traffic_ID": np.arange(1, total_len + 1),
        "Random_Forest": np.where(is_attack, "Attack", "Normal"),
        "Anomaly_Detection": np.where(is_anomaly, "Anomaly", "Normal"),
        "Final_Result": np.where(hybrid_result, "Attack", "Normal"),
        "Attack_Category": attk_cats,
        "Attack_Probability": np.round(rf_probabilities * 100, 2),
        "Risk_Score": scores,
        "Risk_Level": risk_lvls,
        "Detection_Reason": reasons
    })


def export_report(results):
    REPORT_DIR.mkdir(exist_ok=True)
    report_path = REPORT_DIR / "network_detection_report.csv"
    results.to_csv(report_path, index=False)
    return report_path


def display_summary(results):
    print("\n========== DETECTION SUMMARY ==========")
    print("Total Records :", len(results))
    print("Attack Records:", (results["Final_Result"] == "Attack").sum())
    print("Normal Records:", (results["Final_Result"] == "Normal").sum())
    print("\nRisk Level Distribution:")
    print(results["Risk_Level"].value_counts())
    if "Attack_Category" in results.columns:
        print("\nAttack Category Distribution:")
        print(results["Attack_Category"].value_counts())


if __name__ == "__main__":
    print("\nLoading test network traffic...")
    _, X_test, _, _ = preprocess_datasets()
    sample_data = X_test.iloc[:50].copy()

    print("\nRunning AI Detection Engine...")
    detection_results = detect_network_traffic(sample_data)
    print("\nSample Results:")
    print(detection_results[["Traffic_ID", "Final_Result", "Attack_Category", "Attack_Probability", "Risk_Score", "Risk_Level"]].head(10).to_string())
    display_summary(detection_results)
