import pandas as pd
import joblib
from pathlib import Path
from sklearn.preprocessing import OrdinalEncoder

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENCODER_PATH = PROJECT_ROOT / "models" / "feature_encoder.pkl"
TRAIN_DATA_PATH = PROJECT_ROOT / "data" / "UNSW_NB15_training-set.csv"
TEST_DATA_PATH = PROJECT_ROOT / "data" / "UNSW_NB15_testing-set.csv"


def load_datasets():
    """Loads UNSW-NB15 training and testing CSV datasets from project data directory."""
    if not TRAIN_DATA_PATH.exists() or not TEST_DATA_PATH.exists():
        raise FileNotFoundError(
            f"Dataset files missing. Expected at:\n - {TRAIN_DATA_PATH}\n - {TEST_DATA_PATH}"
        )

    train_df = pd.read_csv(TRAIN_DATA_PATH)
    test_df = pd.read_csv(TEST_DATA_PATH)

    return train_df, test_df


def preprocess_datasets(include_attack_cat=False):
    """Preprocesses training and testing datasets using OrdinalEncoder for categoricals.

    Preserves encoder state in models/feature_encoder.pkl.
    
    Args:
        include_attack_cat: If True, returns (X_train, X_test, y_train, y_test, y_train_cat, y_test_cat).
                            If False (default), returns (X_train, X_test, y_train, y_test) for backward compatibility.
    """
    train_df, test_df = load_datasets()

    y_train = train_df["label"].copy()
    y_test = test_df["label"].copy()

    y_train_cat = train_df["attack_cat"].fillna("Normal").astype(str).str.strip().copy()
    y_test_cat = test_df["attack_cat"].fillna("Normal").astype(str).str.strip().copy()

    drop_columns = ["id", "label", "attack_cat"]

    X_train = train_df.drop(columns=[col for col in drop_columns if col in train_df.columns])
    X_test = test_df.drop(columns=[col for col in drop_columns if col in test_df.columns])

    categorical_columns = ["proto", "service", "state"]
    categorical_columns = [col for col in categorical_columns if col in X_train.columns]

    # Load existing encoder if present to guarantee 100% encoder consistency
    if ENCODER_PATH.exists():
        saved_pkg = joblib.load(ENCODER_PATH)
        encoder = saved_pkg["encoder"]
    else:
        encoder = OrdinalEncoder(
            handle_unknown="use_encoded_value",
            unknown_value=-1
        )
        encoder.fit(X_train[categorical_columns])
        ENCODER_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "encoder": encoder,
            "categorical_columns": categorical_columns
        }, ENCODER_PATH)

    X_train[categorical_columns] = encoder.transform(X_train[categorical_columns])
    X_test[categorical_columns] = encoder.transform(X_test[categorical_columns])

    if include_attack_cat:
        return X_train, X_test, y_train, y_test, y_train_cat, y_test_cat

    return X_train, X_test, y_train, y_test


if __name__ == "__main__":
    X_train, X_test, y_train, y_test, y_tr_cat, y_te_cat = preprocess_datasets(include_attack_cat=True)
    print("Preprocessing completed successfully!")
    print("Training features:", X_train.shape)
    print("Testing features:", X_test.shape)
    print("Training labels:", y_train.shape)
    print("Testing labels:", y_test.shape)
    print("Attack categories (train):", y_tr_cat.nunique(), "distinct classes")
    print("Attack categories (test):", y_te_cat.nunique(), "distinct classes")
    print("Encoder verified at:", ENCODER_PATH)
