import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import accuracy_score, classification_report

# Load datasets
train_data = pd.read_csv("UNSW_NB15_training-set.csv")
test_data = pd.read_csv("UNSW_NB15_testing-set.csv")

# Remove ID column
train_data.drop("id", axis=1, inplace=True)
test_data.drop("id", axis=1, inplace=True)

# Separate features and labels
X_train = train_data.drop(["label", "attack_cat"], axis=1)
y_train = train_data["label"]

X_test = test_data.drop(["label", "attack_cat"], axis=1)
y_test = test_data["label"]

# Convert categorical data
X_train = pd.get_dummies(X_train)
X_test = pd.get_dummies(X_test)
X_test = X_test.reindex(columns=X_train.columns, fill_value=0)

# Train Random Forest model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1
)

print("Training started...")
model.fit(X_train, y_train)
# Train Isolation Forest using normal traffic only
normal_traffic = X_train[y_train == 0]

isolation_model = IsolationForest(
    contamination="auto",
    random_state=42
)

isolation_model.fit(normal_traffic)

print("Isolation Forest Training Completed!")

# Test model
predictions = model.predict(X_test)
# Detect anomalies using Isolation Forest
anomaly_predictions = isolation_model.predict(X_test)

print("\nIsolation Forest Detection Completed!")
print("Anomalies Detected:", (anomaly_predictions == -1).sum())

print("\nModel Training Completed!")
print("Accuracy:", accuracy_score(y_test, predictions))
print("\nClassification Report:")
print(classification_report(y_test, predictions))

# Save model
joblib.dump(isolation_model, "isolation_forest_model.pkl")
import joblib

joblib.dump(model, "intrusion_model.pkl")
joblib.dump(isolation_model, "isolation_forest_model.pkl")

print("Both models saved successfully!")