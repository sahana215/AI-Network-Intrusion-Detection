# BLACKBOX
## AI-Powered Network Intrusion Detection & SOC Platform

**An Intelligent Network Defense and Security Operations Platform**

BLACKBOX is an AI-powered Network Intrusion Detection and Security Operations Center (SOC) platform built to monitor network traffic, detect suspicious activities, analyze threats, assess security risks, and generate incident reports through a centralized dashboard.

It combines supervised machine learning, anomaly detection, live packet capture, network flow analysis, threat intelligence enrichment, and SOC reporting into one platform.

---

## Key Features

- **AI-Based Intrusion Detection:** Random Forest classification and Isolation Forest anomaly detection.
- **Live Network Monitoring:** Packet capture and network flow analysis using Scapy.
- **Dataset-Based Detection:** Analysis using the UNSW-NB15 dataset.
- **Behavioral Analysis:** Identification of suspicious network activity and attack patterns.
- **Threat Intelligence:** Curated IP reputation data, SQLite caching, and optional AbuseIPDB integration.
- **Risk Assessment:** Risk scoring with LOW, MEDIUM, HIGH, and CRITICAL levels.
- **Explainability:** Detection explanations and threat-related insights.
- **SOC Dashboard:** Centralized monitoring of alerts, incidents, and network activity.
- **Automated Reporting:** Generation of security incident reports.

---

## Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python |
| Dashboard | Streamlit |
| Machine Learning | Scikit-learn |
| Data Processing | Pandas, NumPy |
| Visualization | Plotly |
| Packet Capture | Scapy |
| Database | SQLite |
| Model Serialization | Joblib |
| Report Generation | ReportLab |

---

## AI Detection Architecture

BLACKBOX uses two machine learning approaches.

### 1. Random Forest – Supervised Learning

- Trained using labeled UNSW-NB15 network traffic.
- Learns patterns from normal and attack traffic.
- Classifies network flows as Normal or Attack.
- Produces attack probability scores.

### 2. Isolation Forest – Unsupervised Anomaly Detection

- Trained using normal network traffic.
- Identifies unusual network behavior.
- Generates anomaly indicators to support threat analysis.

### 3. Hybrid Detection Workflow

The platform combines classification and anomaly detection to provide additional detection context.

**Dataset evaluation:** The evaluated OR-based hybrid combines Random Forest and Isolation Forest predictions.

**Live detection:** The live engine uses a Random Forest probability threshold of 0.70 for its final Attack/Normal verdict. Isolation Forest contributes anomaly information to risk analysis; it does not independently override that final verdict.

This distinction is important because the dataset evaluation workflow and live detection workflow are not identical.

---

## Model Evaluation Results

The following results were obtained during evaluation on the UNSW-NB15 testing dataset.

| Metric | Random Forest | Isolation Forest | OR Hybrid |
|---|---:|---:|---:|
| Accuracy | 92.39% | 46.16% | 90.34% |
| Precision | 96.21% | 58.37% | 91.61% |
| Recall | 89.72% | 7.73% | 90.78% |
| F1-Score | 92.85% | 13.64% | 91.19% |
| False Positive Rate | 4.33% | 6.75% | 10.19% |

### Confusion Matrices

Rows represent actual labels and columns represent predicted labels. The order is Normal, Attack.

**Random Forest**

| | Predicted Normal | Predicted Attack |
|---|---:|---:|
| Actual Normal | 35,397 | 1,603 |
| Actual Attack | 4,661 | 40,671 |

**Isolation Forest**

| | Predicted Normal | Predicted Attack |
|---|---:|---:|
| Actual Normal | 34,502 | 2,498 |
| Actual Attack | 41,830 | 3,502 |

**OR Hybrid**

| | Predicted Normal | Predicted Attack |
|---|---:|---:|
| Actual Normal | 33,229 | 3,771 |
| Actual Attack | 4,179 | 41,153 |

### Evaluation Observations

- Random Forest achieved the strongest overall F1-score among these evaluated approaches.
- Isolation Forest showed limited attack recall in this evaluation.
- The OR hybrid improved attack recall compared with Random Forest but increased the false positive rate.
- Model performance should be considered alongside false positives, false negatives, and the operational requirements of an IDS.

These are dataset evaluation results, not guaranteed real-world detection rates.

---

## Dataset

**Dataset:** UNSW-NB15 Network Intrusion Detection Dataset.

The project uses separate training and testing CSV files:

- `UNSW_NB15_training-set.csv`
- `UNSW_NB15_testing-set.csv`

The training dataset is used for model training, while the separate testing dataset is used for evaluation.

Categorical feature encoding is fitted using training data and applied to testing data.

The public GitHub repository currently includes the testing CSV. The training CSV is maintained in the local project and is not currently included in the public repository.

To reproduce training, obtain the corresponding official UNSW-NB15 training file and place it in the expected `data/` directory.

---

## Live Network Feature Extraction

BLACKBOX uses Scapy to capture packets and build bidirectional network flows.

The live flow engine extracts network statistics and maps them into the 22 model input features:

`dur`, `proto`, `service`, `state`, `spkts`, `dpkts`, `sbytes`, `dbytes`, `rate`, `sload`, `dload`, `sinpkt`, `dinpkt`, `sjit`, `djit`, `swin`, `dwin`, `tcprtt`, `synack`, `ackdat`, `smean`, `dmean`.

### How Live Feature Extraction Works

1. Capture packets from an authorized network interface.
2. Identify source and destination endpoints.
3. Track bidirectional network flows.
4. Calculate packet counts, byte counts, timing statistics, and other flow-level values.
5. Map the extracted values into the model's expected feature order.
6. Pass the generated flow features to the live AI detection engine.

**Feature compatibility note:** UNSW-NB15 contains precomputed flow features. BLACKBOX calculates corresponding flow-level statistics from captured packets. These calculations are an implementation-specific approximation and should not be interpreted as an exact reproduction of the original UNSW-NB15 feature extraction process.

---

## Threat Intelligence

BLACKBOX uses a combination of offline and optional online threat intelligence.

- Curated offline IP reputation entries covering selected Tor, scanning, C2, botnet, and safe DNS resolver addresses.
- SQLite database caching for reputation information.
- Private and bogon IP checks.
- Optional AbuseIPDB API integration when an API key is configured.
- Unknown public IP addresses can be classified as unverified.

The offline list is curated data, not a continuously updated threat feed. API availability and reputation results depend on the configured external service.

---

## Risk Assessment

The risk engine calculates a risk score using available detection context, including:

- Random Forest attack probability.
- Isolation Forest anomaly information.
- Attack category.
- Destination port.
- Packet rate.
- Additional behavior and threat intelligence inputs where supplied.

Risk levels:

| Score | Risk Level |
|---|---|
| 0–34 | LOW |
| 35–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

Risk scores are indicators for investigation and should not be treated as confirmed incidents by themselves.

---

## Project Structure

```text
AI-Network-Intrusion-Detection/
│
├── app.py
├── app_backup.py
├── eval_metrics.py
├── requirements.txt
├── README.md
│
├── assets/
│
├── data/
│   ├── UNSW_NB15_training-set.csv
│   └── UNSW_NB15_testing-set.csv
│
├── database/
│   ├── blackbox_soc.db
│   └── blackbox_threat_intel.db
│
├── models/
│   ├── attack_classifier_model.pkl
│   ├── feature_encoder.pkl
│   ├── hybrid_intrusion_model.pkl
│   ├── live_hybrid_intrusion_model.pkl
│   └── live_hybrid_intrusion_model.pre_ttl_fix.pkl
│
├── modules/
│   ├── attack_behaviour_engine.py
│   ├── attack_classifier.py
│   ├── connection_tracker.py
│   ├── detection_engine.py
│   ├── explainability_engine.py
│   ├── flow_engine.py
│   ├── live_ai_engine.py
│   ├── live_capture.py
│   ├── preprocessing.py
│   ├── report_generator.py
│   ├── risk_engine.py
│   ├── soc_database.py
│   ├── threat_intel.py
│   └── train_model.py
│
├── reports/
│
└── tests/
    └── test_blackbox_suite.py
```

Database files, generated incident reports, and local environment files are excluded from the public repository to avoid exposing sensitive or machine-specific data.

---

## Installation and Setup

### Prerequisites

- Python 3.10 or compatible Python version.
- pip package manager.
- Windows or Linux.
- Npcap installed on Windows for live packet capture.
- Administrator privileges on Windows or appropriate root/capture permissions on Linux for packet capture.

### 1. Clone the Repository

```bash
git clone https://github.com/sahana215/AI-Network-Intrusion-Detection.git
```

### 2. Navigate to the Project

```bash
cd AI-Network-Intrusion-Detection
```

### 3. Create a Virtual Environment

```bash
python -m venv venv
```

### 4. Activate the Virtual Environment

**Windows PowerShell**

```powershell
.\venv\Scripts\Activate.ps1
```

**Windows Command Prompt**

```cmd
venv\Scripts\activate.bat
```

**Linux**

```bash
source venv/bin/activate
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the Application

```bash
streamlit run app.py
```

The BLACKBOX dashboard will open in your browser.

**Note:** Live packet capture requires the appropriate network interface and operating-system permissions. Dataset-based analysis and live capture are separate workflows. The public repository may not contain private databases, trained model artifacts, or the training dataset; these may need to be generated or configured locally before all workflows can run.

---

## Testing

The project includes a test suite:

```bash
python -m pytest tests/
```

Model evaluation can be run using:

```bash
python eval_metrics.py
```

---

## Project Status

**Development Status: Completed**

BLACKBOX brings together AI-based network intrusion detection, live traffic monitoring, flow analysis, threat intelligence enrichment, risk assessment, SOC incident visibility, and automated reporting in a unified platform.

---

## Author

**Sahana S**

Cyber Security Student

GitHub: [sahana215](https://github.com/sahana215)

Project: [AI Network Intrusion Detection – BLACKBOX](https://github.com/sahana215/AI-Network-Intrusion-Detection)

---

## Disclaimer

BLACKBOX is developed for educational and defensive cybersecurity purposes. Network monitoring and packet capture must only be performed on systems and networks for which proper authorization has been obtained. Detection outputs are indicators for investigation and should be validated before being treated as confirmed security incidents.
