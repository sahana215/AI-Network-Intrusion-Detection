
import streamlit as st
import pandas as pd
import joblib

st.set_page_config(page_title="AI Network Intrusion Detection", layout="wide")

st.title("AI Network Intrusion Detection System")
st.write("SOC Dashboard - Network Traffic Monitoring")

# Load both trained models
model = joblib.load("intrusion_model.pkl")
isolation_model = joblib.load("isolation_forest_model.pkl")

# Load datasets
train_data = pd.read_csv("UNSW_NB15_training-set.csv")
test_data = pd.read_csv("UNSW_NB15_testing-set.csv")

# Prepare features
X_train = train_data.drop(["id", "label", "attack_cat"], axis=1)
X_test = test_data.drop(["id", "label", "attack_cat"], axis=1)

X_train = pd.get_dummies(X_train)
X_test = pd.get_dummies(X_test)
X_test = X_test.reindex(columns=X_train.columns, fill_value=0)

# Random Forest predictions
predictions = model.predict(X_test)
risk_scores = model.predict_proba(X_test)[:, 1]

# Isolation Forest predictions
anomaly_predictions = isolation_model.predict(X_test)

# Store results
results = test_data.copy()

results["Prediction"] = predictions
results["Status"] = results["Prediction"].map({
    0: "Normal",
    1: "Attack"
})

results["Anomaly Status"] = pd.Series(
    anomaly_predictions, index=results.index
).map({
    1: "Normal",
    -1: "Anomaly"
})

results["Risk Score (%)"] = (risk_scores * 100).round(2)

results["Risk Level"] = pd.cut(
    risk_scores,
    bins=[-0.001, 0.5, 0.8, 1.001],
    labels=["Low", "Medium", "High"]
)

# Dashboard metrics
total = len(results)
attacks = (predictions == 1).sum()
normal = (predictions == 0).sum()
anomalies = (anomaly_predictions == -1).sum()

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Traffic", total)
col2.metric("Normal Traffic", normal)
col3.metric("Detected Attacks", attacks)
col4.metric("Anomalies Detected", anomalies)

# Traffic overview
st.subheader("Traffic Overview")
st.bar_chart(results["Status"].value_counts())

# Attack category analysis
st.subheader("Attack Category Analysis")
attack_counts = results[
    results["Prediction"] == 1
]["attack_cat"].value_counts()

st.bar_chart(attack_counts)

st.subheader("Attack Category Details")
st.dataframe(attack_counts)

# Anomaly analysis
st.subheader("Anomaly Detection Analysis")
st.bar_chart(results["Anomaly Status"].value_counts())

# Network traffic analysis
st.subheader("Network Traffic Analysis")
st.dataframe(results[[
    "proto", "service", "state", "spkts",
    "dpkts", "sbytes", "dbytes",
    "Status", "Risk Score (%)", "Risk Level",
    "Anomaly Status"
]])

# Detected attacks
st.subheader("Detected Attacks")
st.dataframe(results[results["Prediction"] == 1])

# Detected anomalies
st.subheader("Detected Anomalies")
st.dataframe(results[results["Anomaly Status"] == "Anomaly"])

# SOC recommendations
st.subheader("SOC Analyst Recommendations")

st.write("1. High Risk: Investigate the suspicious network traffic.")
st.write("2. Medium Risk: Monitor the network activity.")
st.write("3. Low Risk: Continue routine monitoring.")
st.write("4. Anomaly: Investigate unusual network behaviour.")
st.header("Live Network Monitoring")

if st.button("View Latest Live Predictions"):
    live_results = pd.read_csv("live_prediction_results.csv")

    st.subheader("Live Traffic Predictions")

    st.dataframe(live_results[[
        "Source IP",
        "Destination IP",
        "proto",
        "spkts",
        "dpkts",
        "Attack Prediction",
        "Anomaly Prediction"
    ]])

    st.metric(
        "Live Attacks",
        (live_results["Attack Prediction"] == "Attack").sum()
    )

    st.metric(
        "Live Anomalies",
        (live_results["Anomaly Prediction"] == "Anomaly").sum()
    )
