# BLACKBOX
## AI-Powered Network Intrusion Detection & SOC Platform

**An AI-driven cybersecurity platform for network intrusion detection, live traffic monitoring, threat analysis, and Security Operations Center (SOC) operations.**

---

## Project Overview

BLACKBOX is an AI-powered Network Intrusion Detection and SOC Monitoring Platform developed to analyze network traffic, identify potentially suspicious activities, assess security risks, and support security monitoring.

The project brings together network traffic processing, attack classification, live capture, AI-based analysis, threat intelligence, and reporting components through a centralized Streamlit application.

It also supports offline network traffic analysis using the UNSW-NB15 dataset.

## Core Components

### 1. Network Traffic Analysis
- Network traffic preprocessing.
- Network flow processing.
- Connection tracking.
- Live network traffic capture.

### 2. AI-Based Detection
- Attack classification.
- Detection engine.
- Live AI detection engine.
- Attack behaviour analysis.

### 3. Security Risk Analysis
- Risk assessment engine.
- Suspicious activity analysis.
- Explainability engine for detection analysis.

### 4. Threat Intelligence
- Threat intelligence processing.
- Threat intelligence database integration.
- SOC database integration.

### 5. Reporting and Evaluation
- Network detection report generation.
- PDF report generation.
- Model evaluation metrics.
- Automated project test suite.

## Technology Stack

| Category | Technology |
|---|---|
| Programming Language | Python |
| Web Application | Streamlit |
| Data Processing | Pandas, NumPy |
| Machine Learning | Scikit-learn |
| Data Visualization | Plotly |
| Network Monitoring | Live Packet Capture |
| Database | SQLite |
| Reporting | PDF Generation |
| Dataset | UNSW-NB15 |

## Project Architecture

The application is organized into separate Python components to handle network processing, detection, risk analysis, threat intelligence, database operations, and reporting.

```text
AI-Network-Intrusion-Detection/
│
├── app.py
├── requirements.txt
├── eval_metrics.py
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
├── train_model.py
├── test_blackbox_suite.py
│
├── UNSW_NB15_testing-set.csv
├── live_flows_dump.csv
├── network_detection_report.csv
│
├── blackbox_soc.db
└── blackbox_threat_intel.db
```

## Dataset

**UNSW-NB15**

The project includes the `UNSW_NB15_testing-set.csv` dataset file for network traffic analysis and intrusion detection evaluation.

Live traffic monitoring and offline dataset analysis are separate workflows.

## Installation and Setup

### Prerequisites

- Python 3.10 or later
- pip package manager
- Windows or Linux environment

### 1. Clone the Repository

```bash
git clone https://github.com/sahana215/AI-Network-Intrusion-Detection.git
```

### 2. Navigate to the Project Directory

```bash
cd AI-Network-Intrusion-Detection
```

### 3. Create a Virtual Environment

```bash
python -m venv venv
```

### 4. Activate the Virtual Environment

**Windows:**

```bash
venv\Scripts\activate
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the Application

```bash
streamlit run app.py
```

The application will launch in the default web browser.

## Model Evaluation

The project includes `eval_metrics.py` for model evaluation and `train_model.py` for model training workflows.

Evaluation results should be interpreted separately from live network monitoring results.

## Project Objectives

- Develop an AI-powered network intrusion detection platform.
- Analyze network traffic and identify suspicious behaviour.
- Support live network traffic monitoring.
- Provide attack classification and risk analysis.
- Integrate threat intelligence and SOC database components.
- Generate security analysis reports.

## Project Status

**Development Status: Completed**

BLACKBOX combines network intrusion detection, live traffic monitoring, security analysis, threat intelligence, and SOC monitoring components in a unified application.

## Author

**Sahana S**

Cyber Security Student

GitHub: [@sahana215](https://github.com/sahana215)

**Repository:** [AI-Network-Intrusion-Detection](https://github.com/sahana215/AI-Network-Intrusion-Detection)

---

## Disclaimer

This project is intended for educational and defensive cybersecurity purposes. Live network monitoring must only be performed on networks for which proper authorization has been obtained. AI-generated detection results should be reviewed before being treated as confirmed security incidents.
