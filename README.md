# AI Network Intrusion Detection System

### Machine Learning-Based Network Attack & Anomaly Detection

An intelligent network security monitoring system combining supervised and unsupervised machine learning, live packet capture, and a SOC-style dashboard.

---

## 1. Project Overview

The **AI Network Intrusion Detection System** is a cybersecurity project designed to identify potentially malicious network traffic and detect unusual network behaviour using machine learning techniques.

The system uses the UNSW-NB15 dataset to train and evaluate machine learning models. It also integrates live packet capture using Scapy to extract network traffic features and perform live predictions.

A Streamlit-based dashboard provides a centralized interface to monitor network traffic, detected attacks, and anomalies.

## 2. Key Objectives

- Identify normal and malicious network traffic.
- Detect unusual network behaviour using anomaly detection.
- Capture and analyse live network packets.
- Extract meaningful network flow features.
- Provide visual network security monitoring through a dashboard.

## 3. System Architecture

```text
UNSW-NB15 Dataset
        |
        v
Data Preprocessing
        |
        v
Feature Extraction
        |
        v
Machine Learning Models
   /             \
Random Forest   Isolation Forest
   |                 |
Attack Detection   Anomaly Detection
   \                 /
        |
        v
Live Packet Capture (Scapy)
        |
        v
Network Flow Extraction
        |
        v
Live Traffic Prediction
        |
        v
Streamlit SOC Dashboard
```

## 4. Machine Learning Models

### Random Forest Classifier

A supervised machine learning algorithm used to classify network traffic into:
- Normal Traffic
- Attack Traffic

**Test Dataset Accuracy: 87.25%**

### Isolation Forest

An unsupervised anomaly detection algorithm trained using normal network traffic to identify unusual patterns that may indicate suspicious activity.

Both algorithms are implemented as separate models for network attack classification and anomaly detection.

## 5. Live Network Monitoring

Live packet monitoring is implemented using **Scapy**.

The monitoring module captures network packets and extracts:

- Source IP Address
- Destination IP Address
- Protocol
- Packet Size
- Time
- TTL (Time To Live)

The captured information is stored in CSV format for further processing.

## 6. Network Flow Feature Extraction

Captured packets are grouped into bidirectional network flows.

The system extracts the following features:

| Feature | Description |
|---|---|
| `spkts` | Forward packet count |
| `dpkts` | Reverse packet count |
| `sbytes` | Forward bytes |
| `dbytes` | Reverse bytes |
| `dur` | Flow duration |
| `rate` | Packet rate |
| `sttl` | Source TTL |
| `dttl` | Destination TTL |
| `smean` | Average forward packet size |
| `dmean` | Average reverse packet size |

## 7. SOC Monitoring Dashboard

The interactive dashboard is developed using **Streamlit**.

Dashboard capabilities:

- Total network traffic monitoring
- Normal traffic statistics
- Attack detection statistics
- Anomaly detection statistics
- Attack category analysis
- Network traffic details
- Live prediction results
- SOC analyst recommendations

## 8. Technology Stack

| Category | Technologies |
|---|---|
| Programming Language | Python |
| Dataset | UNSW-NB15 |
| Data Processing | Pandas, NumPy |
| Machine Learning | Scikit-learn |
| Classification | Random Forest |
| Anomaly Detection | Isolation Forest |
| Packet Capture | Scapy |
| Dashboard | Streamlit |
| Data Visualization | Matplotlib |

## 9. Project Structure

```text
AI-Network-Intrusion-Detection/
│
├── app.py
├── train_model.py
├── live_model.py
├── live_monitor.py
├── flow_extraction.py
├── live_prediction.py
├── check_features.py
│
├── requirements.txt
├── README.md
│
└── screenshots/
```

## 10
