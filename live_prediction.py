
import pandas as pd
import joblib

# Load trained models
rf_model = joblib.load("live_intrusion_model.pkl")
if_model = joblib.load("live_isolation_model.pkl")

# Load live network flows
df = pd.read_csv("live_network_flows.csv")

# Select model features
features = [
    "dur", "proto", "spkts", "dpkts",
    "sbytes", "dbytes", "rate",
    "sttl", "dttl", "smean", "dmean"
]

X_live = df[features].copy()

# Convert protocol into numeric columns
X_live = pd.get_dummies(X_live)

# Match training model columns
X_live = X_live.reindex(
    columns=rf_model.feature_names_in_,
    fill_value=0
)

# Random Forest prediction
rf_predictions = rf_model.predict(X_live)

# Isolation Forest prediction
if_predictions = if_model.predict(X_live)

# Add results
df["Attack Prediction"] = [
    "Attack" if p == 1 else "Normal"
    for p in rf_predictions
]

df["Anomaly Prediction"] = [
    "Anomaly" if p == -1 else "Normal"
    for p in if_predictions
]

# Save prediction results
df.to_csv("live_prediction_results.csv", index=False)

print("Live Network Prediction Completed!")
print(df[[
    "Source IP",
    "Destination IP",
    "Attack Prediction",
    "Anomaly Prediction"
]])

print("\nResults saved as live_prediction_results.csv")
