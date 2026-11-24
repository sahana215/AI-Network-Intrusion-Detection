# BLACKBOX
## AI-Powered Network Intrusion Detection & SOC Platform

**An intelligent cybersecurity platform combining machine learning-based intrusion detection, network traffic analysis, live monitoring, and SOC-focused security operations.**

---

## 1. Project Overview

BLACKBOX is an AI-powered Network Intrusion Detection and Security Operations Center (SOC) platform developed to analyze network traffic and identify potentially malicious activities.

The project combines supervised machine learning, unsupervised anomaly detection, network flow processing, live packet capture, attack behaviour analysis, risk assessment, threat intelligence, and security reporting.

A Streamlit-based dashboard provides a centralized interface for network security monitoring and analysis.

## 2. Key Features

### Network Traffic Analysis
- Network traffic preprocessing.
- Network flow processing and analysis.
- Connection tracking.
- Live network packet capture.

### Hybrid AI-Based Intrusion Detection
- Random Forest-based attack classification.
- Isolation Forest-based anomaly detection.
- Combined detection results using a hybrid approach.
- Model training and evaluation.

### Attack Behaviour Analysis
- Suspicious network behaviour analysis.
- Attack pattern identification.
- Network activity investigation.

### Risk Assessment
- Risk scoring and classification.
- Suspicious activity assessment.
- Detection result analysis.

### Threat Intelligence
- Threat intelligence processing.
- Threat intelligence database integration.

### SOC Monitoring
- Centralized security dashboard.
- Alert and incident monitoring.
- Network security analysis.

### Explainability & Reporting
- Detection result explanations.
- Security report generation.
- CSV-based network analysis records.
- PDF report generation.

## 3. System Architecture

```text
             NETWORK TRAFFIC / DATASET
                        |
             +----------+----------+
             |                     |
        Live Capture           Offline Dataset
             |                     |
       Network Flow          Preprocessing
        Processing                 |
             |               Feature Extraction
             |                     |
             +----------+----------+
                        |
                 AI Detection
                        |
              +---------+---------+
              |                   |
         Random Forest       Isolation Forest
         Classification      Anomaly Detection
              |                   |
              +---------+---------+
                        |
                 Hybrid Detection
                        |
              Attack Behaviour Analysis
                        |
                  Risk Assessment
                        |
          +-------------+-------------+
          |             |             |
     Threat Intel   SOC Database  Explainability
          |             |             |
          +-------------+-------------+
                        |
                Streamlit Dashboard
                        |
                  PDF Reporting
```

## 4. Machine Learning Approach

**Random Forest Classifier**

A supervised machine learning algorithm used to classify network traffic into normal and attack categories.

**Isolation Forest**

An unsupervised anomaly detection algorithm used to identify unusual network traffic patterns.

**Hybrid Detection**

The training workflow combines Random Forest and Isolation Forest predictions to identify potentially malicious traffic.

## 5. Technology Stack

| Category | Technologies |
|---|---|
| Programming Language | Python |
| Web Dashboard | Streamlit |
| Machine Learning | Scikit-learn |
| Classification | Random Forest |
| Anomaly Detection | Isolation Forest |
| Data Processing | Pandas, NumPy |
| Visualization | Plotly |
| Packet Capture | Scapy |
| Graph Processing | NetworkX |
| Database | SQLite |
| PDF Reporting | ReportLab |

## 6. Dataset

**UNSW-NB15 Network Intrusion Detection Dataset**

The repository includes `UNSW_NB15_testing-set.csv` for network traffic analysis and evaluation.

The project distinguishes between offline dataset analysis and live network monitoring. Offline evaluation results should not be interpreted as live network detection accuracy.

## 7. Project Structure

```text
AI-Network-Intrusion-Detection/
│
├── app.py
├── requirements.txt
├── eval_metrics.py
├── train_model.py
│
├── attack_behaviour_engine.py
├── attack_classifier.py
├── connection_tracker.py
├── detection_engine.py
├── explainability_engine.py
├── flow_engine.py
├── live_ai_engine.py
├── live_capture.py
├── preprocessing.py
├── report_generator.py
├── risk_engine.py
├── soc_database.py
├── threat_intel.py
│
├── test_blackbox_suite.py
│
├── UNSW_NB15_testing-set.csv
├── live_flows_dump.csv
├── network_detection_report.csv
│
├── blackbox_soc.db
└── blackbox_threat_intel.db
```

## 8. Installation

### Prerequisites
- Python 3.10 or later
- pip package manager
- Appropriate permissions for live packet capture

### Step 1: Clone the Repository

```bash
git clone https://github.com/sahana215/AI-Network-Intrusion-Detection.git
```

### Step 2: Navigate to the Project Directory

```bash
cd AI-Network-Intrusion-Detection
```

### Step 3: Create a Virtual Environment

```bash
python -m venv venv
```

### Step 4: Activate the Environment

**Windows:**

```bash
venv\Scripts\activate
```

### Step 5: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 6: Launch the Dashboard

```bash
streamlit run app.py
```

## 9. Project Objectives

- Develop an AI-powered network intrusion detection platform.
- Identify suspicious network traffic and abnormal behaviour.
- Integrate supervised and unsupervised machine learning techniques.
- Support live network monitoring and flow analysis.
- Provide risk assessment and threat intelligence capabilities.
- Support SOC monitoring and security reporting.

## 10. Project Status

**Development Status: Completed**

BLACKBOX brings together machine learning-based network intrusion detection, live traffic monitoring, attack behaviour analysis, threat intelligence, and SOC-oriented monitoring in a unified cybersecurity platform.

## 11. Author

**Sahana S**

Cyber Security Student

GitHub: [@sahana215](https://github.com/sahana215)

**Project Repository:** [BLACKBOX – AI Network Intrusion Detection](https://github.com/sahana215/AI-Network-Intrusion-Detection)

---

## Disclaimer

This project is developed for educational and defensive cybersecurity purposes. Live network monitoring and testing must only be performed on networks for which proper authorization has been obtained. AI-generated detection results should be reviewed before being treated as confirmed security incidents.
