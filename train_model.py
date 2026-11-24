
import joblib
import numpy as np

from pathlib import Path

from sklearn.ensemble import (
    RandomForestClassifier,
    IsolationForest
)

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score
)

from modules.preprocessing import preprocess_datasets


def evaluate_model(name, y_true, predictions):

    print(f"\n========== {name} ==========")

    print(f"Accuracy  : {accuracy_score(y_true, predictions) * 100:.2f}%")
    print(f"Precision : {precision_score(y_true, predictions, zero_division=0) * 100:.2f}%")
    print(f"Recall    : {recall_score(y_true, predictions, zero_division=0) * 100:.2f}%")
    print(f"F1 Score  : {f1_score(y_true, predictions, zero_division=0) * 100:.2f}%")

    print("\nClassification Report:")
    print(classification_report(
        y_true,
        predictions,
        target_names=["Normal", "Attack"],
        zero_division=0
    ))

    print("Confusion Matrix:")
    print(confusion_matrix(y_true, predictions))


def train_detection_models():

    print("\nLoading datasets...")

    X_train, X_test, y_train, y_test = preprocess_datasets()

    # Reduce memory usage
    X_train = X_train.astype(np.float32)
    X_test = X_test.astype(np.float32)

    encoder_package = joblib.load("models/feature_encoder.pkl")

    print("Categorical encoder loaded!")
    print("Training data converted to float32.")

    # RANDOM FOREST

    print("\nTraining Random Forest...")

    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=2
    )

    rf_model.fit(X_train, y_train)

    rf_predictions = rf_model.predict(X_test)

    evaluate_model(
        "RANDOM FOREST RESULTS",
        y_test,
        rf_predictions
    )

    # ISOLATION FOREST

    print("\nTraining Isolation Forest...")

    normal_traffic = X_train.loc[y_train == 0]

    isolation_model = IsolationForest(
        n_estimators=100,
        contamination="auto",
        random_state=42,
        n_jobs=2
    )

    isolation_model.fit(normal_traffic)

    print("Isolation Forest training completed!")

    isolation_raw = isolation_model.predict(X_test)

    isolation_predictions = np.where(
        isolation_raw == -1,
        1,
        0
    )

    evaluate_model(
        "ISOLATION FOREST RESULTS",
        y_test,
        isolation_predictions
    )

    # HYBRID DETECTION

    print("\nCombining detection results...")

    hybrid_predictions = np.where(
        (rf_predictions == 1) |
        (isolation_predictions == 1),
        1,
        0
    )

    evaluate_model(
        "HYBRID DETECTION RESULTS",
        y_test,
        hybrid_predictions
    )

    # SAVE MODELS

    print("\nSaving trained models...")

    model_dir = Path("models")
    model_dir.mkdir(exist_ok=True)

    model_package = {
        "random_forest": rf_model,
        "isolation_forest": isolation_model,
        "feature_columns": X_train.columns.tolist(),
        "encoder": encoder_package["encoder"],
        "categorical_columns": encoder_package["categorical_columns"]
    }

    joblib.dump(
        model_package,
        model_dir / "hybrid_intrusion_model.pkl"
    )

    print("\n====================================")
    print("HYBRID AI TRAINING COMPLETED!")
    print("Random Forest: Saved")
    print("Isolation Forest: Saved")
    print("Encoder: Integrated")
    print("Model: models/hybrid_intrusion_model.pkl")
    print("====================================")


if __name__ == "__main__":
    train_detection_models()
