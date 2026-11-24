# BLACKBOX
## AI-Powered Network Intrusion Detection & SOC Platform

**An Intelligent Network Defense and Security Operations Platform**

BLACKBOX is an AI-powered Network Intrusion Detection and Security Operations Center (SOC) platform built to bring network visibility, intelligent threat detection, behavioral analysis, and security incident investigation into a unified environment.

Designed around a centralized SOC operations console, BLACKBOX combines network monitoring, dataset intelligence, AI-driven detection, threat intelligence, risk analysis, incident visibility, and automated security reporting.

The platform aims to support security monitoring and investigation through a structured, intelligence-driven workflow.

---

## Platform Overview

BLACKBOX provides a centralized **Network Defense Intelligence Platform** through a dedicated SOC dashboard.

Its interface is organized into eight operational workspaces:

| Workspace | Purpose |
|---|---|
| Command Center | Centralized SOC overview and operational posture |
| Network Monitoring | Network traffic monitoring and visibility |
| Dataset Intelligence | Dataset-based network security analysis |
| AI Detection Engine | AI-powered intrusion detection |
| Threat Intelligence Hub | Threat intelligence analysis |
| SOC Alerts & Incidents | Security alert and incident visibility |
| Threat Analytics & Tuning | Behavioral threat analytics and detection tuning |
| Automated Security Reports | Security reporting and documentation |

---

## Core Capabilities

### AI-Powered Network Intrusion Detection
- Hybrid AI-based network detection workflow
- Network traffic classification and analysis
- Suspicious activity identification
- Anomaly detection capabilities

### Live Network Monitoring
- Live network traffic capture
- Network flow analysis
- Connection tracking
- Monitoring of network activity

### Behavioral Threat Analytics
- Attack behaviour analysis
- Suspicious activity investigation
- Threat pattern analysis
- Risk-based security assessment

### Threat Intelligence
- Threat intelligence integration
- Threat-related analysis
- Intelligence-supported investigation

### SOC Operations
- Centralized security command center
- Alert and incident visibility
- Operational security monitoring
- Security analysis and investigation support

### Security Reporting
- Automated security report generation
- Detection and analysis documentation
- Security investigation reporting

---

## Platform Architecture

BLACKBOX follows a modular architecture that separates traffic processing, detection, analysis, intelligence, and reporting.

```text
                  NETWORK INPUT
                        |
             +----------+----------+
             |                     |
       LIVE TRAFFIC             DATASET
             |                     |
             +----------+----------+
                        |
                TRAFFIC PROCESSING
                        |
                  FLOW ANALYSIS
                        |
                AI DETECTION ENGINE
                        |
             BEHAVIOURAL ANALYSIS
                        |
                 RISK ASSESSMENT
                        |
              THREAT INTELLIGENCE
                        |
              SOC ALERT MANAGEMENT
                        |
              CENTRALIZED DASHBOARD
                        |
              SECURITY REPORTING
```

---

## Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Web Dashboard | Streamlit |
| Machine Learning | Scikit-learn |
| Data Processing | Pandas, NumPy |
| Data Visualization | Plotly |
| Network Packet Analysis | Scapy |
| Database | SQLite |
| Report Generation | ReportLab |

---

## Dataset

**UNSW-NB15 Network Intrusion Detection Dataset**

The project repository includes the `UNSW_NB15_testing-set.csv` dataset for network intrusion detection analysis.

BLACKBOX supports dataset-based analysis and live network monitoring as distinct workflows.

---

## Repository Structure

```text
AI-Network-Intrusion-Detection/
│
├── app.py
├── requirements.txt
│
├── train_model.py
├── eval_metrics.py
├── test_blackbox_suite.py
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
├── UNSW_NB15_testing-set.csv
└── network_detection_report.csv
```

---

## Installation & Setup

### Prerequisites

- Python 3.x
- pip package manager
- Required Python dependencies
- Appropriate permissions for authorized live packet capture

### Step 1 — Clone the Repository

```bash
git clone https://github.com/sahana215/AI-Network-Intrusion-Detection.git
```

### Step 2 — Navigate to the Project

```bash
cd AI-Network-Intrusion-Detection
```

### Step 3 — Create a Virtual Environment

```bash
python -m venv venv
```

### Step 4 — Activate the Environment

**Windows:**

```bash
venv\Scripts\activate
```

### Step 5 — Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 6 — Launch BLACKBOX

```bash
streamlit run app.py
```

The application will start locally and provide access to the BLACKBOX SOC dashboard through your browser.

---

## Project Objectives

- Build an integrated AI-powered network intrusion detection platform.
- Improve visibility into network activity and suspicious behaviour.
- Support both live traffic monitoring and dataset-based analysis.
- Integrate threat intelligence into network security analysis.
- Provide a centralized environment for SOC alert and incident visibility.
- Support investigation through behavioral analytics and risk assessment.
- Generate structured security reports.

---

## Project Status

**Development Status: Completed**

BLACKBOX is a completed project that brings together AI-powered network intrusion detection, live monitoring, threat intelligence, behavioral analytics, SOC operations, and automated security reporting in a unified platform.

---

## Author

**Sahana S**

Cyber Security Student

**GitHub:** [github.com/sahana215](https://github.com/sahana215)

**Project Repository:** [AI Network Intrusion Detection – BLACKBOX](https://github.com/sahana215/AI-Network-Intrusion-Detection)

---

## Disclaimer

BLACKBOX is developed for educational and defensive cybersecurity purposes. Network monitoring and packet capture must only be performed on systems and networks for which proper authorization has been obtained. Detection outputs should be validated before being treated as confirmed security incidents.
