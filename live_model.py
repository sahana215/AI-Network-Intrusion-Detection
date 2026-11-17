
import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, classification_report

# Load datasets
train_data = pd.read_csv("UNSW_NB15_training-set.csv")
test_data = pd.read_csv("UNSW_NB15_testing-set.csv")

# Select matching features
features = [
    "dur", "proto", "spkts", "dpkts",
    "sbytes", "dbytes", "rate",
    "sttl", "dttl", "smean", "dmean"
]

X_train = train_data[features]
y_train = train_data["label"]

X_test = test_data[features]
y_test = test_data["label"]

# Convert categorical features
X_train = pd.get_dummies(X_train)
X_test = pd.get_dummies(X_test)

X_test = X_test.reindex(
    columns=X_train.columns,
    fill_value=0
)

print("Training Features:", X_train.shape)
print("Testing Features:", X_test.shape)

# Random Forest Model
rf_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

print("\nRandom Forest Training Started...")
rf_model.fit(X_train, y_train)

rf_predictions = rf_model.predict(X_test)

print("\nRandom Forest Accuracy:",
      accuracy_score(y_test, rf_predictions))

print("\nRandom Forest Classification Report:")
print(classification_report(y_test, rf_predictions))

# Isolation Forest Model
normal_traffic = X_train[y_train == 0]

if_model = IsolationForest(
    contamination="auto",
    random_state=42
)

print("\nIsolation Forest Training Started...")
if_model.fit(normal_traffic)

if_predictions = if_model.predict(X_test)

anomalies = (if_predictions == -1).sum()

print("\nIsolation Forest Results:")
print("Total Test Traffic:", len(X_test))
print("Normal Traffic:", (if_predictions == 1).sum())
print("Anomalies Detected:", anomalies)

# Save both models
joblib.dump(rf_model, "live_intrusion_model.pkl")
joblib.dump(if_model, "live_isolation_model.pkl")

print("\nBoth Live Models Saved Successfully!")

