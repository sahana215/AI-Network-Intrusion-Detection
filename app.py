
import os
from datetime import datetime
from io import BytesIO
from html import escape
import sys
import logging

os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"

logger = logging.getLogger("BLACKBOX.App")

import threading
import time
from queue import Queue, Empty
from collections import deque
from pathlib import Path

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import sniff

from modules.preprocessing import preprocess_datasets, PROJECT_ROOT
from modules.detection_engine import load_models, detect_network_traffic, preprocess_live_traffic
from modules.live_capture import extract_packet_info, get_available_interfaces
from modules.flow_engine import FlowAggregator
from modules.live_ai_engine import detect_live_flows, ATTACK_THRESHOLD
from modules.attack_behaviour_engine import detect_attack_behaviours, profile_network_hosts
from modules.attack_classifier import classify_attack_flows, ATTACK_SEVERITY_MAP
from modules.risk_engine import calculate_composite_risk_score, CRITICAL_PORTS
from modules.threat_intel import ThreatIntelEngine, get_ip_reputation
from modules.soc_database import SOCDatabase
from modules.connection_tracker import ConnectionTracker
from modules.explainability_engine import AIExplainabilityEngine, explain_single_flow
from modules.report_generator import generate_csv_report, generate_pdf_report


# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="BLACKBOX | NIDS SOC Platform",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="expanded"
)


# =====================================================
# BLACKBOX DESIGN SYSTEM (CYBER DEFENSE THEME)
# =====================================================

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');

:root {
    --black: #09090c;
    --panel: #111116;
    --panel2: #18181f;
    --border: #292932;
    --red: #ed174c;
    --red-bright: #ff315c;
    --white: #f4f4f7;
    --muted: #92929f;
}

.stApp {
    background:
        radial-gradient(ellipse at 85% 5%, rgba(237,23,76,0.09), transparent 35%),
        #09090c;
    color: var(--white);
    font-family: 'Manrope', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
}

[data-testid="stAppViewContainer"] {
    background: transparent;
}

[data-testid="stHeader"] {
    background: rgba(9,9,12,0.85);
}

.block-container {
    max-width: 1580px;
    padding-top: 1.8rem;
    padding-bottom: 3rem;
}

.stMarkdown, .stMarkdown p, .stMarkdown li, .stMarkdown span {
    color: #e4e4eb;
}

h1, h2, h3, h4 {
    color: #ffffff !important;
}

label, .stCaption, [data-testid="stCaptionContainer"] {
    color: #aaaab6 !important;
}

/* SIDEBAR */
[data-testid="stSidebar"] {
    background: #0d0d12;
    border-right: 1px solid #292932;
}

[data-testid="stSidebar"] > div:first-child {
    padding: 22px 16px;
}

[data-testid="stSidebar"] p, [data-testid="stSidebar"] label {
    color: #c7c7d0;
}

[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {
    color: #ffffff !important;
}

[data-testid="stSidebar"] [data-testid="stRadio"] label {
    padding: 10px 12px;
    border-radius: 9px;
    margin-bottom: 4px;
    transition: 0.2s ease;
}

[data-testid="stSidebar"] [data-testid="stRadio"] label:hover {
    background: #25121a;
}

[data-testid="stSidebar"] [data-testid="stRadio"] label:has(input:checked) {
    background: #32121e;
    border-left: 3px solid #ed174c;
}

/* BRAND */
.brand {
    padding: 20px 16px;
    background: linear-gradient(145deg, #1b1118, #111116);
    border: 1px solid #572033;
    border-radius: 14px;
    margin-bottom: 24px;
    box-shadow: 0 0 25px rgba(237,23,76,0.08);
}

.brand-symbol {
    font-size: 32px;
    color: #ff315c;
    font-weight: 800;
    text-shadow: 0 0 18px rgba(255,49,92,0.65);
}

.brand-name {
    color: #ffffff;
    font-size: 22px;
    font-weight: 800;
    letter-spacing: 3px;
}

.brand-sub {
    color: #a6a0aa;
    font-family: 'DM Mono', monospace;
    font-size: 9px;
    letter-spacing: 2px;
    margin-top: 6px;
}

/* HERO */
.hero {
    background:
        radial-gradient(circle at 85% 30%, rgba(237,23,76,0.2), transparent 28%),
        linear-gradient(120deg, #171116, #0e0e13 70%);
    border: 1px solid #4b1b2b;
    border-radius: 18px;
    padding: 28px 32px;
    color: white;
    position: relative;
    overflow: hidden;
    margin-bottom: 26px;
    box-shadow: 0 10px 40px rgba(0,0,0,0.25);
}

.hero:after {
    content: "⬡";
    position: absolute;
    right: 40px;
    top: -55px;
    font-size: 210px;
    color: #ed174c;
    opacity: 0.08;
}

.hero-label {
    font-family: 'DM Mono', monospace;
    color: #ff456c;
    letter-spacing: 3px;
    font-size: 10px;
    position: relative;
    z-index: 1;
}

.hero-title {
    color: #ffffff;
    font-size: 32px;
    font-weight: 800;
    margin-top: 14px;
    position: relative;
    z-index: 1;
}

.hero-description {
    color: #bdb8c1;
    font-size: 13px;
    margin-top: 8px;
    position: relative;
    z-index: 1;
}

.hero-tag {
    display: inline-block;
    margin-top: 18px;
    padding: 8px 14px;
    border-radius: 6px;
    background: #ed174c;
    color: #ffffff;
    font-family: 'DM Mono', monospace;
    font-size: 10px;
    font-weight: 700;
    position: relative;
    z-index: 1;
}

/* PAGE TITLES */
.page-kicker {
    color: #ff456c;
    font-family: 'DM Mono', monospace;
    font-size: 10px;
    letter-spacing: 2px;
    font-weight: 700;
}

.page-title {
    font-size: 26px;
    font-weight: 800;
    color: #ffffff;
    margin-top: 4px;
}

.page-desc {
    color: #9999a5;
    font-size: 12px;
    margin-bottom: 22px;
}

/* METRICS */
[data-testid="stMetric"] {
    background: linear-gradient(145deg, #19191f, #111116);
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #30303a;
    border-bottom: 3px solid #ed174c;
    box-shadow: 0 6px 20px rgba(0,0,0,0.18);
}

[data-testid="stMetricLabel"] {
    color: #aaaab6 !important;
    font-size: 11px !important;
    font-weight: 700 !important;
    letter-spacing: 1px;
}

[data-testid="stMetricValue"] {
    color: #ffffff !important;
    font-size: 26px !important;
    font-weight: 800 !important;
}

/* SECTIONS */
.section-title {
    color: #ffffff;
    font-size: 15px;
    font-weight: 800;
    margin-top: 22px;
    margin-bottom: 12px;
    border-left: 3px solid #ed174c;
    padding-left: 10px;
}

/* CHARTS */
[data-testid="stPlotlyChart"] {
    background: #111116;
    border: 1px solid #30303a;
    border-radius: 12px;
    padding: 8px;
}

/* DATAFRAMES */
[data-testid="stDataFrame"] {
    background: #111116;
    border: 1px solid #30303a;
    border-radius: 11px;
}

/* BUTTONS */
.stButton > button {
    background: linear-gradient(100deg, #a90f36, #ed174c);
    color: #ffffff !important;
    border: 1px solid #ff315c;
    border-radius: 8px;
    min-height: 42px;
    font-weight: 800;
    letter-spacing: 0.5px;
    transition: 0.2s ease;
}

.stButton > button:hover {
    background: #ff315c;
    border-color: #ff607f;
    box-shadow: 0 0 18px rgba(237,23,76,0.28);
}

.stDownloadButton > button {
    background: #20121a;
    color: #ff456c !important;
    border: 1px solid #ed174c;
    border-radius: 8px;
    font-weight: 800;
    min-height: 42px;
}

/* FOOTER */
.footer {
    border-top: 1px solid #30303a;
    margin-top: 40px;
    padding-top: 16px;
    color: #858591;
    font-family: 'DM Mono', monospace;
    font-size: 10px;
    letter-spacing: 1px;
    text-align: center;
}

.footer span {
    color: #ff456c;
}
</style>
""", unsafe_allow_html=True)


# =====================================================
# PROJECT PATHS & GLOBAL CACHE
# =====================================================

MODEL_PATH = PROJECT_ROOT / "models" / "hybrid_intrusion_model.pkl"
LIVE_MODEL_PATH = PROJECT_ROOT / "models" / "live_hybrid_intrusion_model.pkl"
ATTACK_MODEL_PATH = PROJECT_ROOT / "models" / "attack_classifier_model.pkl"
REPORT_DIR = PROJECT_ROOT / "reports"
REPORT_DIR.mkdir(exist_ok=True)

BATCH_SIZE = 2500

soc_db = SOCDatabase()


# =====================================================
# SESSION STATE INITIALIZATION
# =====================================================

if "live_packet_queue" not in st.session_state:
    st.session_state.live_packet_queue = Queue(maxsize=1000)

if "live_packets" not in st.session_state:
    st.session_state.live_packets = deque(maxlen=500)

if "live_flow_summaries" not in st.session_state:
    st.session_state.live_flow_summaries = []

if "live_flow_history" not in st.session_state:
    st.session_state.live_flow_history = {}

if "live_detection_history" not in st.session_state:
    st.session_state.live_detection_history = {}

if "live_session_metadata" not in st.session_state:
    st.session_state.live_session_metadata = {
        "start_time": None,
        "end_time": None,
        "interface": None,
        "status": "NOT STARTED"
    }

if "live_capture_stats" not in st.session_state:
    st.session_state.live_capture_stats = {
        "packet_count": 0,
        "preview_dropped": 0
    }

if "live_last_error" not in st.session_state:
    st.session_state.live_last_error = None

if "live_monitoring" not in st.session_state:
    st.session_state.live_monitoring = False

if "live_stop_event" not in st.session_state:
    st.session_state.live_stop_event = None

if "live_thread" not in st.session_state:
    st.session_state.live_thread = None

if "conn_tracker" not in st.session_state:
    st.session_state.conn_tracker = ConnectionTracker()


# =====================================================
# MODEL CACHING & DETECTION HELPERS
# =====================================================

@st.cache_resource
def get_ai_models():
    return load_models()
def _live_flows_to_dataframe(flows):
    """Normalize live flow summaries from FlowAggregator into a DataFrame."""
    if flows is None:
        return pd.DataFrame()

    if isinstance(flows, pd.DataFrame):
        return flows.copy()

    if isinstance(flows, dict):
        return pd.DataFrame([flows])

    if isinstance(flows, (list, tuple, deque)):
        records = []
        for flow in flows:
            if isinstance(flow, dict):
                records.append(flow)
            elif hasattr(flow, "_asdict"):
                records.append(flow._asdict())
            elif hasattr(flow, "__dict__"):
                records.append(vars(flow))
        return pd.DataFrame(records)

    try:
        return pd.DataFrame(flows)
    except (TypeError, ValueError):
        logger.warning("Unsupported live flow summary type: %s", type(flows).__name__)
        return pd.DataFrame()


def archive_live_flows(flows):
    flows_df = _live_flows_to_dataframe(flows)
    if flows_df.empty:
        return

    history = st.session_state.live_flow_history

    for _, row in flows_df.iterrows():
        flow = row.to_dict()

        flow_id = str(flow.get("Flow ID", ""))
        start_time = str(flow.get("Start Time", ""))

        if not flow_id:
            flow_id = (
                f"{flow.get('Source IP', '')}-"
                f"{flow.get('Destination IP', '')}-"
                f"{flow.get('Source Port', '')}-"
                f"{flow.get('Destination Port', '')}-"
                f"{flow.get('Protocol', '')}"
            )

        key = (flow_id, start_time)
        history[key] = flow


def archive_live_detections(detection_df, flow_df):
    if detection_df is None:
        return

    if not isinstance(detection_df, pd.DataFrame):
        try:
            detection_df = pd.DataFrame(detection_df)
        except (TypeError, ValueError):
            logger.warning("Unsupported live detection result type: %s", type(detection_df).__name__)
            return

    if detection_df.empty:
        return

    flow_df = _live_flows_to_dataframe(flow_df)
    history = st.session_state.live_detection_history
    flow_times = {}

    if not flow_df.empty:
        for _, row in flow_df.iterrows():
            flow_id = str(row.get("Flow ID", ""))
            flow_times[flow_id] = {
                "Start Time": row.get("Start Time", ""),
                "Last Time": row.get("Last Time", "")
            }

    for _, row in detection_df.iterrows():
        detection = row.to_dict()
        flow_id = str(detection.get("Flow ID", ""))

        if not flow_id:
            flow_id = (
                f"{detection.get('Source IP', '')}-"
                f"{detection.get('Destination IP', '')}-"
                f"{detection.get('Source Port', '')}-"
                f"{detection.get('Destination Port', '')}-"
                f"{detection.get('Protocol', '')}"
            )

        times = flow_times.get(flow_id, {})
        detection["Start Time"] = times.get("Start Time", detection.get("Start Time", ""))
        detection["Last Time"] = times.get("Last Time", detection.get("Last Time", ""))

        key = (flow_id, str(detection["Start Time"]))
        history[key] = detection


def drain_live_queue():
    packet_q = st.session_state.live_packet_queue

    while True:
        try:
            item = packet_q.get_nowait()

            if not isinstance(item, dict):
                continue

            if "packet" in item:
                st.session_state.live_packets.append(item["packet"])

            elif "flows" in item:
                # FlowAggregator currently returns a list of flow dictionaries.
                # Normalize it before using DataFrame methods such as .empty.
                flows_df = _live_flows_to_dataframe(item["flows"])
                if not flows_df.empty:
                    st.session_state.live_flow_summaries = flows_df.to_dict("records")
                    archive_live_flows(flows_df)

            elif "error" in item:
                logger.error("Live capture error: %s", item["error"])
                st.session_state.live_last_error = str(item["error"])

        except Empty:
            break
        except Exception as queue_err:
            logger.error("Error while draining live capture queue: %s", queue_err, exc_info=True)
            st.session_state.live_last_error = str(queue_err)
            break


def stop_live_session(status="STOPPED"):
    stop_event = st.session_state.get("live_stop_event")
    worker = st.session_state.get("live_thread")

    if stop_event:
        stop_event.set()

    if worker and worker.is_alive():
        worker.join(timeout=3)

    drain_live_queue()

    metadata = st.session_state.live_session_metadata
    if metadata.get("start_time"):
        metadata["end_time"] = datetime.now().astimezone().isoformat(
            timespec="seconds"
        )

    metadata["status"] = status
    st.session_state.live_monitoring = False


def generate_live_monitoring_pdf():
    """Build a PDF strictly from flows and detections archived during live capture."""
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, KeepTogether
    )

    metadata = dict(st.session_state.live_session_metadata)
    flow_records = list(st.session_state.live_flow_history.values())
    detection_records = list(st.session_state.live_detection_history.values())
    flow_df = pd.DataFrame(flow_records)
    detection_df = pd.DataFrame(detection_records)

    packet_count = int(st.session_state.live_capture_stats.get("packet_count", 0))
    attack_count = 0
    anomaly_count = 0
    high_count = 0
    critical_count = 0

    if not detection_df.empty:
        if "Final_Result" in detection_df.columns:
            attack_count = int((detection_df["Final_Result"] == "Attack").sum())
        if "Anomaly_Detection" in detection_df.columns:
            anomaly_count = int((detection_df["Anomaly_Detection"] == "Anomaly").sum())
        if "Risk_Level" in detection_df.columns:
            high_count = int((detection_df["Risk_Level"] == "HIGH").sum())
            critical_count = int((detection_df["Risk_Level"] == "CRITICAL").sum())

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=13 * mm,
        bottomMargin=13 * mm,
        title="BLACKBOX Live Network Monitoring Report",
        author="BLACKBOX NIDS SOC Platform"
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", parent=styles["Title"],
        fontName="Helvetica-Bold", fontSize=19,
        textColor=colors.HexColor("#A90F36"),
        alignment=TA_CENTER, spaceAfter=5 * mm
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", parent=styles["Heading2"],
        textColor=colors.HexColor("#A90F36"),
        fontSize=11, spaceBefore=5 * mm, spaceAfter=2 * mm
    ))
    styles.add(ParagraphStyle(
        name="SmallCell", parent=styles["BodyText"],
        fontSize=7, leading=8
    ))

    story = [
        Paragraph("BLACKBOX — LIVE MONITORING REPORT", styles["ReportTitle"]),
        Paragraph(
            "Evidence in this report is generated from packets captured during the live monitoring session. "
            "It does not use the offline benchmark dataset.",
            styles["BodyText"]
        ),
        Spacer(1, 4 * mm)
    ]

    session_rows = [
        ["Session Start", str(metadata.get("start_time") or "Not recorded")],
        ["Session End", str(metadata.get("end_time") or "Not recorded")],
        ["Network Interface", str(metadata.get("interface") or "Not recorded")],
        ["Session Status", str(metadata.get("status") or "UNKNOWN")],
    ]
    session_table = Table(session_rows, colWidths=[42 * mm, 210 * mm])
    session_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F1E5E9")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#222222")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BBBBBB")),
        ("PADDING", (0, 0), (-1, -1), 6),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))
    story += [
        Paragraph("1. Capture Session Details", styles["SectionHeading"]),
        session_table,
        Paragraph("2. Live Capture Summary", styles["SectionHeading"])
    ]

    summary_rows = [
        ["Metric", "Recorded Value"],
        ["Packets captured", f"{packet_count:,}"],
        ["Unique flow records archived", f"{len(flow_df):,}"],
        ["Attack verdicts", f"{attack_count:,}"],
        ["Anomalies flagged", f"{anomaly_count:,}"],
        ["High-risk detections", f"{high_count:,}"],
        ["Critical-risk detections", f"{critical_count:,}"],
        ["Packet preview records dropped (queue full)", str(
            st.session_state.live_capture_stats.get("preview_dropped", 0)
        )]
    ]
    summary_table = Table(summary_rows, colWidths=[85 * mm, 45 * mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#292932")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BBBBBB")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
        ("PADDING", (0, 0), (-1, -1), 6)
    ]))
    story.append(summary_table)

    if not detection_df.empty and "Attack_Category" in detection_df.columns:
        story.append(Paragraph("3. Detection Category Breakdown", styles["SectionHeading"]))
        category_counts = detection_df["Attack_Category"].fillna("Unknown").astype(str).value_counts()
        category_rows = [["Category", "Count"]] + [
            [str(category), str(count)] for category, count in category_counts.items()
        ]
        category_table = Table(category_rows, colWidths=[90 * mm, 30 * mm], repeatRows=1)
        category_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#292932")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BBBBBB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
            ("PADDING", (0, 0), (-1, -1), 5)
        ]))
        story.append(category_table)

    story.append(Paragraph("4. Captured Flow Evidence", styles["SectionHeading"]))
    if flow_df.empty:
        story.append(Paragraph(
            "No flow records were archived in this session. Start live monitoring and allow traffic to be captured before generating the report.",
            styles["BodyText"]
        ))
    else:
        preferred = [
            "Start Time", "Last Time", "Source IP", "Destination IP",
            "Source Port", "Destination Port", "Protocol",
            "Flow Duration", "Total Packets", "Total Bytes"
        ]
        columns = [column for column in preferred if column in flow_df.columns]
        if not columns:
            columns = list(flow_df.columns[:10])
        evidence_rows = [[Paragraph(escape(str(c)), styles["SmallCell"]) for c in columns]]
        for _, row in flow_df.head(100).iterrows():
            evidence_rows.append([
                Paragraph(escape(str(row.get(c, "")))[:100], styles["SmallCell"])
                for c in columns
            ])
        widths = [landscape(A4)[0] * 0.92 / max(1, len(columns))] * len(columns)
        evidence_table = Table(evidence_rows, colWidths=widths, repeatRows=1)
        evidence_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#292932")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BBBBBB")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 3)
        ]))
        story.append(evidence_table)

    story.append(Paragraph("5. AI Detection Evidence", styles["SectionHeading"]))
    if detection_df.empty:
        story.append(Paragraph(
            "No live AI detection records were archived for this session.",
            styles["BodyText"]
        ))
    else:
        preferred = [
            "Source IP", "Destination IP", "Protocol", "Final_Result",
            "Attack_Category", "Risk_Score", "Risk_Level", "Detection_Reason"
        ]
        columns = [column for column in preferred if column in detection_df.columns]
        if columns:
            evidence_rows = [[Paragraph(escape(str(c)), styles["SmallCell"]) for c in columns]]
            sorted_df = detection_df.copy()
            if "Risk_Score" in sorted_df.columns:
                sorted_df = sorted_df.sort_values("Risk_Score", ascending=False)
            for _, row in sorted_df.head(100).iterrows():
                evidence_rows.append([
                    Paragraph(escape(str(row.get(c, "")))[:160], styles["SmallCell"])
                    for c in columns
                ])
            widths = [landscape(A4)[0] * 0.92 / len(columns)] * len(columns)
            detection_table = Table(evidence_rows, colWidths=widths, repeatRows=1)
            detection_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#292932")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#BBBBBB")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("PADDING", (0, 0), (-1, -1), 3)
            ]))
            story.append(detection_table)

    story.append(Spacer(1, 5 * mm))
    story.append(Paragraph(
        "Report note: AI verdicts are model-generated triage signals and should be validated by a security analyst. "
        "This report includes up to 100 flow records and 100 detection records.",
        styles["Italic"]
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()


@st.cache_resource(show_spinner=False)
def validate_engine_status():
    """Validates the health and loadability of all 3 AI engine models."""
    status = {}

    # 1. Offline Hybrid Model (42 Features)
    try:
        if not MODEL_PATH.exists():
            status["offline"] = ("NOT_FOUND", "OFFLINE MODEL NOT FOUND")
        else:
            rf, iso, cols, enc, _ = load_models()
            if hasattr(rf, "predict") and hasattr(iso, "predict") and len(cols) == 42 and enc is not None:
                status["offline"] = ("ACTIVE", "OFFLINE RF + IF (42 Feats)")
            else:
                status["offline"] = ("INVALID", "OFFLINE MODEL SCHEMA MISMATCH")
    except Exception as e:
        logger.error(f"Failed to validate offline model: {e}", exc_info=True)
        status["offline"] = ("ERROR", f"OFFLINE LOAD ERROR: {type(e).__name__}")

    # 2. Live Hybrid Model (22 Features)
    try:
        from modules.live_ai_engine import load_live_models
        if not LIVE_MODEL_PATH.exists():
            status["live"] = ("NOT_FOUND", "LIVE MODEL NOT FOUND")
        else:
            pkg = load_live_models()
            rf = pkg.get("random_forest")
            iso = pkg.get("isolation_forest")
            cols = pkg.get("feature_columns", [])
            if hasattr(rf, "predict") and hasattr(iso, "predict") and len(cols) == 22:
                status["live"] = ("ACTIVE", "LIVE AI MODEL (22 Feats)")
            else:
                status["live"] = ("INVALID", "LIVE MODEL SCHEMA MISMATCH")
    except Exception as e:
        logger.error(f"Failed to validate live model: {e}", exc_info=True)
        status["live"] = ("ERROR", f"LIVE LOAD ERROR: {type(e).__name__}")

    # 3. Attack Multiclass Classifier (10 Classes)
    try:
        from modules.attack_classifier import load_attack_classifier
        if not ATTACK_MODEL_PATH.exists():
            status["classifier"] = ("NOT_FOUND", "CLASSIFIER NOT FOUND")
        else:
            pkg = load_attack_classifier()
            clf = pkg.get("classifier")
            classes = pkg.get("classes", [])
            if hasattr(clf, "predict") and len(classes) >= 9:
                status["classifier"] = ("ACTIVE", f"ATTACK CLASSIFIER ({len(classes)} Classes)")
            else:
                status["classifier"] = ("INVALID", "CLASSIFIER SCHEMA MISMATCH")
    except Exception as e:
        logger.error(f"Failed to validate attack classifier: {e}", exc_info=True)
        status["classifier"] = ("ERROR", f"CLASSIFIER ERROR: {type(e).__name__}")

    return status


@st.cache_data(show_spinner=False)
def run_full_detection():
    """Runs high-performance vectorized benchmark detection over the UNSW-NB15 test set with multiclass classification."""
    _, X_test, _, _ = preprocess_datasets()
    rf_model, isolation_model, feature_columns, _, _ = get_ai_models()

    X_test_aligned = X_test.reindex(columns=feature_columns, fill_value=0).astype(np.float32)

    rf_preds = rf_model.predict(X_test_aligned)
    rf_probs = rf_model.predict_proba(X_test_aligned)[:, 1]
    iso_preds = isolation_model.predict(X_test_aligned)

    is_attack = (rf_preds == 1)
    is_anomaly = (iso_preds == -1)
    hybrid = is_attack | is_anomaly

    # Multiclass Attack Classification
    try:
        from modules.attack_classifier import load_attack_classifier
        clf_pkg = load_attack_classifier()
        c_model = clf_pkg["classifier"]
        c_cols = clf_pkg["feature_columns"]
        X_cat = X_test.reindex(columns=c_cols, fill_value=0).astype(np.float32)
        attack_categories = c_model.predict(X_cat)
    except Exception as e:
        logger.warning(f"Attack classification fallback in run_full_detection: {e}")
        attack_categories = np.where(is_attack, "Generic", "Normal")

    prob_pts = rf_probs * 45.0
    anom_pts = np.where(is_anomaly, 15.0, 0.0)
    cat_pts = np.where(is_attack, 10.0, 0.0)
    scores = np.clip(np.round(prob_pts + anom_pts + cat_pts), 0, 100).astype(int)
    risk_lvls = np.where(
        scores >= 80, "CRITICAL",
        np.where(scores >= 60, "HIGH",
                 np.where(scores >= 35, "MEDIUM", "LOW"))
    )

    reasons = [
        f"Confirmed Attack ({cat}) with anomaly pattern" if attk and anom else (
            f"Random Forest identified {cat} signature" if attk else (
                "Isolation Forest flagged anomalous distribution" if anom else
                "Verified within normal baseline traffic boundaries"
            )
        )
        for attk, anom, cat in zip(is_attack, is_anomaly, attack_categories)
    ]

    return pd.DataFrame({
        "Traffic_ID": np.arange(1, len(X_test_aligned) + 1),
        "Random_Forest": np.where(is_attack, "Attack", "Normal"),
        "Anomaly_Detection": np.where(is_anomaly, "Anomaly", "Normal"),
        "Final_Result": np.where(hybrid, "Attack", "Normal"),
        "Attack_Category": attack_categories,
        "Attack_Probability": np.round(rf_probs * 100, 2),
        "Risk_Score": scores,
        "Risk_Level": risk_lvls,
        "Detection_Reason": reasons
    })


def get_results():
    return run_full_detection()


def style_chart(fig):
    fig.update_layout(
        paper_bgcolor="#111116",
        plot_bgcolor="#111116",
        font=dict(color="#eeeeF3", family="Manrope", size=12),
        title_font=dict(color="#ffffff", size=15),
        legend=dict(font=dict(color="#eeeeF3"), bgcolor="rgba(17,17,22,0.7)"),
        margin=dict(t=35, b=25, l=20, r=20)
    )
    fig.update_xaxes(color="#c8c8d2", gridcolor="#292932", zerolinecolor="#383842", linecolor="#383842")
    fig.update_yaxes(color="#c8c8d2", gridcolor="#292932", zerolinecolor="#383842", linecolor="#383842")
    return fig


def page_header(kicker, title, description):
    st.markdown(
        f"""
        <div class="page-kicker">{kicker}</div>
        <div class="page-title">{title}</div>
        <div class="page-desc">{description}</div>
        """,
        unsafe_allow_html=True
    )


# =====================================================
# SIDEBAR CONTROL ROOM
# =====================================================

st.sidebar.markdown("""
<div class="brand">
    <div class="brand-symbol">⬡</div>
    <div class="brand-name">BLACKBOX</div>
    <div class="brand-sub">AI NETWORK INTRUSION DEFENSE</div>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("### SOC WORKSPACES")

page = st.sidebar.radio(
    "Console",
    [
        "Command Center",
        "Network Monitoring",
        "Dataset Intelligence",
        "AI Detection Engine",
        "Threat Intelligence Hub",
        "SOC Alerts & Incidents",
        "Threat Analytics & Tuning",
        "Automated Security Reports",
    ],
    label_visibility="collapsed"
)

# Prevent abandoned background threads upon workspace navigation
if "current_workspace" not in st.session_state:
    st.session_state.current_workspace = page
elif st.session_state.current_workspace != page:
    if st.session_state.current_workspace == "Network Monitoring" and st.session_state.get("live_monitoring", False):
        stop_live_session(status="STOPPED - WORKSPACE NAVIGATION")
        logger.info("Stopped live network monitoring worker due to workspace navigation.")
    st.session_state.current_workspace = page

st.sidebar.markdown("---")
st.sidebar.markdown("### ENGINE STATUS")

engine_status = validate_engine_status()

if engine_status["offline"][0] == "ACTIVE":
    st.sidebar.success(f"● {engine_status['offline'][1]}")
elif engine_status["offline"][0] == "NOT_FOUND":
    st.sidebar.error(f"○ {engine_status['offline'][1]}")
else:
    st.sidebar.warning(f"⚠ {engine_status['offline'][1]}")

if engine_status["live"][0] == "ACTIVE":
    st.sidebar.success(f"● {engine_status['live'][1]}")
elif engine_status["live"][0] == "NOT_FOUND":
    st.sidebar.error(f"○ {engine_status['live'][1]}")
else:
    st.sidebar.warning(f"⚠ {engine_status['live'][1]}")

if engine_status["classifier"][0] == "ACTIVE":
    st.sidebar.success(f"● {engine_status['classifier'][1]}")
elif engine_status["classifier"][0] == "NOT_FOUND":
    st.sidebar.error(f"○ {engine_status['classifier'][1]}")
else:
    st.sidebar.warning(f"⚠ {engine_status['classifier'][1]}")

st.sidebar.markdown("---")
try:
    soc_metrics = soc_db.get_soc_metrics()
    st.sidebar.caption(f"Active Alerts: **{soc_metrics['new_alerts']}** / Total: **{soc_metrics['total_alerts']}**")
    st.sidebar.caption(f"Open Incidents: **{soc_metrics['open_incidents']}**")
    st.sidebar.caption(f"False Positives Logged: **{soc_metrics['false_positives']}**")
except Exception as db_err:
    logger.error(f"Sidebar SOC telemetry retrieval error: {db_err}", exc_info=True)
    st.sidebar.error(f"DB Telemetry Error: {db_err}")
    soc_metrics = None


# =====================================================
# 1. COMMAND CENTER (SOC COMMAND DASHBOARD - FEATURE 20)
# =====================================================

if page == "Command Center":
    st.markdown("""
    <div class="hero">
        <div class="hero-label">BLACKBOX / SOC OPERATIONS CONSOLE</div>
        <div class="hero-title">NETWORK DEFENSE INTELLIGENCE PLATFORM</div>
        <div class="hero-description">
            AI-Powered Hybrid Network Intrusion Detection, Behavioral Threat Analytics,
            Forensic Incident Investigation, and Automated SOC Security Reporting.
        </div>
        <div class="hero-tag">⬡ HYBRID AI DEFENSE ENGINE ACTIVE</div>
    </div>
    """, unsafe_allow_html=True)

    page_header(
        "01 / OVERVIEW",
        "Security Command Center",
        "Centralized SOC operations console: active alerts, threat landscape, and live posture."
    )

    # 1. LIVE SOC OPERATIONAL TELEMETRY
    st.markdown('<div class="section-title">LIVE SOC OPERATIONAL POSTURE (REAL-TIME TELEMETRY)</div>', unsafe_allow_html=True)
    if soc_metrics is not None:
        op1, op2, op3, op4 = st.columns(4)
        op1.metric("ACTIVE ALERTS (NEW)", f"{soc_metrics['new_alerts']}")
        op2.metric("TOTAL ALERTS LOGGED", f"{soc_metrics['total_alerts']}")
        op3.metric("OPEN INCIDENTS", f"{soc_metrics['open_incidents']}")
        op4.metric("CONFIRMED FALSE POSITIVES", f"{soc_metrics['false_positives']}")
    else:
        st.error("Live SOC operational metrics are unavailable due to a database access error. Check logs for details.")

    # 2. OFFLINE AI DEFENSE BENCHMARK TELEMETRY
    st.markdown('<div class="section-title">OFFLINE AI DEFENSE BENCHMARK (UNSW-NB15 EVALUATION)</div>', unsafe_allow_html=True)
    try:
        with st.spinner("Compiling threat posture telemetry..."):
            results = get_results()

        total = len(results)
        attacks = int((results["Final_Result"] == "Attack").sum())
        normal = int((results["Final_Result"] == "Normal").sum())
        critical = int((results["Risk_Level"] == "CRITICAL").sum())
        high = int((results["Risk_Level"] == "HIGH").sum())

        b1, b2, b3, b4 = st.columns(4)
        b1.metric("BENCHMARK FLOWS", f"{total:,}")
        b2.metric("ATTACKS IDENTIFIED", f"{attacks:,}")
        b3.metric("NORMAL BASELINE", f"{normal:,}")
        b4.metric("CRITICAL RISK FLOWS", f"{critical:,}")

        st.markdown('<div class="section-title">THREAT LANDSCAPE & RISK DISTRIBUTION</div>', unsafe_allow_html=True)

        col_left, col_right = st.columns(2)

        with col_left:
            st.markdown("**Traffic Classification (Hybrid AI)**")
            traffic_df = pd.DataFrame({
                "Traffic": ["Attack", "Normal"],
                "Records": [attacks, normal]
            })
            fig_pie = px.pie(
                traffic_df,
                names="Traffic",
                values="Records",
                hole=0.65,
                color="Traffic",
                color_discrete_map={"Attack": "#ed174c", "Normal": "#4f4f5c"}
            )
            fig_pie.update_traces(textposition="inside", textinfo="percent+label", textfont_color="#ffffff")
            st.plotly_chart(style_chart(fig_pie), width="stretch")

        with col_right:
            st.markdown("**Risk Score Distribution (Composite 0-100)**")
            risk_counts = results["Risk_Level"].value_counts().reindex(["LOW", "MEDIUM", "HIGH", "CRITICAL"], fill_value=0).reset_index()
            risk_counts.columns = ["Risk", "Count"]

            fig_bar = px.bar(
                risk_counts,
                x="Risk",
                y="Count",
                color="Risk",
                text="Count",
                color_discrete_map={
                    "LOW": "#525260",
                    "MEDIUM": "#ffb347",
                    "HIGH": "#ff704d",
                    "CRITICAL": "#ed174c"
                }
            )
            fig_bar.update_traces(textposition="outside", textfont_color="#ffffff")
            st.plotly_chart(style_chart(fig_bar), width="stretch")

        st.markdown('<div class="section-title">RECENT HIGH-RISK INCIDENTS & EVIDENCE</div>', unsafe_allow_html=True)
        high_risk_sample = results[results["Risk_Level"].isin(["CRITICAL", "HIGH"])].head(12)
        st.dataframe(high_risk_sample, width="stretch", hide_index=True)

    except Exception as err:
        logger.error(f"Command Center initialization error: {err}", exc_info=True)
        st.error(f"Command Center initialization error: {err}")


# =====================================================
# 2. NETWORK MONITORING (FEATURES 1, 6, 7, 14, 15)
# =====================================================

elif page == "Network Monitoring":
    page_header(
        "02 / LIVE MONITORING",
        "Real-Time Traffic Inspection",
        "Packet capture, flow extraction, deep protocol analysis, and live AI threat classification."
    )

    ifaces = get_available_interfaces()
    iface_map = {i["id"]: i["label"] for i in ifaces}
    iface_ids = [i["id"] for i in ifaces]

    c_iface, c_stat = st.columns([3, 1])
    with c_iface:
        selected_iface = st.selectbox(
            "Network Interface Adapter",
            options=iface_ids,
            format_func=lambda x: iface_map.get(x, x),
            index=0 if iface_ids else None,
            help="Active physical Wi-Fi/Ethernet adapter is automatically prioritized and pre-selected."
        )

    # Thread-safe background worker (Zero st.session_state access)
    def live_capture_worker(interface_name, packet_q, stop_evt, capture_stats, conn_tracker=None):
        aggregator = FlowAggregator()
        logger.info(f"Background capture worker started on [{interface_name}]")

        def handle_packet(packet):
            try:
                capture_stats["packet_count"] += 1
                pkt_info = extract_packet_info(packet)
                try:
                    packet_q.put_nowait({"packet": pkt_info})
                except Exception:
                    capture_stats["preview_dropped"] += 1
                aggregator.add_packet(packet)
            except Exception as pkt_err:
                logger.debug(f"Packet extraction error: {pkt_err}")

        while not stop_evt.is_set():
            try:
                sniff(
                    iface=interface_name,
                    prn=handle_packet,
                    store=False,
                    timeout=1
                )
                flows = aggregator.get_flow_summary(include_recent_completed=True)
                if conn_tracker is not None:
                    for f in flows:
                        conn_tracker.update_connection(f)

                try:
                    packet_q.put_nowait({"flows": flows})
                except Exception:
                    pass
            except Exception as capture_err:
                logger.error(f"Live sniffing error on {interface_name}: {capture_err}", exc_info=True)
                try:
                    packet_q.put_nowait({"error": str(capture_err)})
                except Exception:
                    pass
                break

        logger.info(f"Background capture worker on [{interface_name}] stopped gracefully.")

    # Check live worker thread health
    is_thread_active = (
        st.session_state.live_thread is not None and
        st.session_state.live_thread.is_alive()
    )
    st.session_state.live_monitoring = is_thread_active

    col1, col2 = st.columns(2)
    with col1:
        if st.button("START LIVE MONITORING", width="stretch", disabled=is_thread_active):
            if not is_thread_active:
                st.session_state.live_packets.clear()
                st.session_state.live_flow_summaries = []
                st.session_state.live_flow_history = {}
                st.session_state.live_detection_history = {}
                st.session_state.live_capture_stats = {
                    "packet_count": 0,
                    "preview_dropped": 0
                }
                st.session_state.live_last_error = None
                st.session_state.live_session_metadata = {
                    "start_time": datetime.now().astimezone().isoformat(timespec="seconds"),
                    "end_time": None,
                    "interface": str(iface_map.get(selected_iface, selected_iface)),
                    "status": "RUNNING"
                }
                st.session_state.live_packet_queue = Queue(maxsize=1000)
                st.session_state.live_stop_event = threading.Event()

                worker = threading.Thread(
                    target=live_capture_worker,
                    args=(
                        selected_iface,
                        st.session_state.live_packet_queue,
                        st.session_state.live_stop_event,
                        st.session_state.live_capture_stats,
                        st.session_state.conn_tracker
                    ),
                    daemon=True
                )
                st.session_state.live_thread = worker
                st.session_state.live_monitoring = True
                worker.start()
                logger.info(f"Live monitoring thread launched for interface: {selected_iface}")
                st.rerun()

    with col2:
        if st.button("STOP LIVE MONITORING", width="stretch", disabled=not is_thread_active):
            stop_live_session(status="STOPPED")
            logger.info("Live monitoring stopped by operator.")
            st.rerun()

    st.markdown("---")

    @st.fragment(run_every=1)
    def live_stream_dashboard():
        drain_live_queue()
        if st.session_state.get("live_last_error"):
            st.error(f"Live Sniffer Error: {st.session_state.live_last_error}")

        packets = list(st.session_state.live_packets)
        flows = st.session_state.live_flow_summaries

        if st.session_state.live_monitoring:
            st.success("LIVE MONITORING ACTIVE — Sniffing and aggregating network flows in real time")
        else:
            st.warning("LIVE MONITORING IDLE — Click 'START LIVE MONITORING' above to capture traffic")

        # Telemetry Bar
        t1, t2, t3, t4 = st.columns(4)
        t1.metric("PACKETS CAPTURED", f"{st.session_state.live_capture_stats.get('packet_count', 0):,}")
        tcp_count = sum(p.get("Protocol") == "TCP" for p in packets)
        udp_count = sum(p.get("Protocol") == "UDP" for p in packets)
        t2.metric("TCP PACKETS", tcp_count)
        t3.metric("UDP PACKETS", udp_count)
        t4.metric("ACTIVE FLOWS", len(flows))

        # Protocol Breakdown Chart (Feature 6)
        if packets:
            st.markdown('<div class="section-title">PROTOCOL ANALYSIS BREAKDOWN</div>', unsafe_allow_html=True)
            proto_df = pd.DataFrame(packets)["Protocol"].value_counts().reset_index()
            proto_df.columns = ["Protocol", "Packets"]
            fig_proto = px.bar(
                proto_df,
                x="Protocol",
                y="Packets",
                color="Protocol",
                text="Packets",
                color_discrete_sequence=["#ed174c", "#3498db", "#f39c12", "#7f8c8d"]
            )
            st.plotly_chart(style_chart(fig_proto), width="stretch")

        # Deep Packet Inspection Table (Feature 14)
        st.markdown('<div class="section-title">DEEP PACKET INSPECTION METADATA</div>', unsafe_allow_html=True)
        if packets:
            pkt_df = pd.DataFrame(packets[-100:])
            st.dataframe(
                pkt_df[["Timestamp", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Packet Size", "TTL", "TCP Flags", "Info", "Payload Hex"]],
                width="stretch",
                hide_index=True
            )
            st.caption("Displaying the 100 most recently inspected packets with TCP flags, TTL, and hex payload snippets.")
        else:
            st.info("No packets captured yet.")

        # Live AI Intrusion Detection Results
        st.markdown('<div class="section-title">LIVE HYBRID AI DETECTION & MULTICLASS CLASSIFICATION</div>', unsafe_allow_html=True)
        if flows:
            try:
                live_df = pd.DataFrame(flows)
                detection_df = detect_live_flows(live_df, auto_alert=True)
                archive_live_detections(detection_df, live_df)

                if detection_df is not None and not detection_df.empty:
                    d_attk = int((detection_df["Final_Result"] == "Attack").sum())
                    d_anom = int((detection_df["Anomaly_Detection"] == "Anomaly").sum())

                    k1, k2, k3 = st.columns(3)
                    k1.metric("FLOWS MONITORED", len(detection_df))
                    k2.metric("ATTACKS DETECTED", d_attk)
                    k3.metric("ANOMALIES FLAGGED", d_anom)

                    st.dataframe(
                        detection_df.sort_values("Risk_Score", ascending=False).head(100),
                        width="stretch",
                        hide_index=True
                    )
                    st.caption("Flows prioritized by composite Attack Risk Score (0-100). Auto-generates deduplicated alerts in SOC Database.")

                # Attack Behaviour Intelligence
                st.markdown('<div class="section-title">ATTACK BEHAVIOUR INTELLIGENCE & HEURISTICS</div>', unsafe_allow_html=True)
                behaviors = detect_attack_behaviours(live_df)
                if not behaviors.empty:
                    st.dataframe(behaviors, width="stretch", hide_index=True)
                else:
                    st.info("No suspicious behavioral patterns (port scanning, SYN flood, brute force) identified in current flows.")

                # Network Connection Tracking (Feature 15)
                st.markdown('<div class="section-title">ACTIVE NETWORK SESSIONS & LIFECYCLE TRACKING</div>', unsafe_allow_html=True)
                sessions = st.session_state.conn_tracker.get_all_sessions(limit=50)
                if sessions:
                    st.dataframe(pd.DataFrame(sessions), width="stretch", hide_index=True)

            except Exception as err:
                logger.error(f"Live detection inference error: {err}", exc_info=True)
                st.error(f"Live detection inference error: {err}")
        else:
            st.info("Waiting for bidirectional network flows to be generated.")

    live_stream_dashboard()


# =====================================================
# 3. DATASET INTELLIGENCE (FEATURE 2)
# =====================================================

elif page == "Dataset Intelligence":
    page_header(
        "03 / DATASET INTELLIGENCE",
        "Upload, Validation & Batch AI Analysis",
        "Upload custom network traffic CSV files, validate feature schema, and run full hybrid AI inference."
    )

    uploaded_file = st.file_uploader("Upload Network Traffic CSV Dataset", type=["csv"])

    if uploaded_file is not None:
        try:
            df_upload = pd.read_csv(uploaded_file)

            u1, u2, u3, u4 = st.columns(4)
            u1.metric("RECORDS", f"{len(df_upload):,}")
            u2.metric("COLUMNS", len(df_upload.columns))
            u3.metric("MISSING VALUES", int(df_upload.isnull().sum().sum()))
            u4.metric("MEMORY USAGE", f"{df_upload.memory_usage().sum() / (1024*1024):.2f} MB")

            # Schema Validation Check
            required_cols = ["dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", "rate"]
            matched_cols = [c for c in required_cols if c in df_upload.columns]
            schema_score = len(matched_cols) / len(required_cols)

            if schema_score >= 0.7:
                st.success(f"SCHEMA VALIDATION PASSED: Matched {len(matched_cols)}/{len(required_cols)} core network flow features.")
            else:
                st.warning(f"PARTIAL SCHEMA MATCH: Matched {len(matched_cols)}/{len(required_cols)} standard features. Missing features will be safely imputed.")

            st.markdown('<div class="section-title">DATASET PREVIEW & FEATURE SUMMARY</div>', unsafe_allow_html=True)
            st.dataframe(df_upload.head(10), width="stretch", hide_index=True)

            # Pre-Inference Exploratory Data Analysis (EDA)
            st.markdown('<div class="section-title">EXPLORATORY DATA ANALYSIS (EDA) & TRAFFIC DISTRIBUTIONS</div>', unsafe_allow_html=True)
            eda_t1, eda_t2, eda_t3 = st.tabs(["Protocols & Services", "Flow Dynamics & Metrics", "Ground Truth Breakdown"])

            with eda_t1:
                col_p1, col_p2 = st.columns(2)
                with col_p1:
                    if "proto" in df_upload.columns:
                        proto_counts = df_upload["proto"].value_counts().head(10).reset_index()
                        proto_counts.columns = ["Protocol", "Count"]
                        fig_proto = px.bar(proto_counts, x="Protocol", y="Count", color="Protocol", text="Count", title="Top Transport Protocols")
                        st.plotly_chart(style_chart(fig_proto), width="stretch")
                    else:
                        st.info("Protocol column ('proto') not found in dataset.")
                with col_p2:
                     if "service" in df_upload.columns:
                        srv_counts = df_upload["service"].value_counts().head(10).reset_index()
                        srv_counts.columns = ["Service", "Count"]
                        fig_srv = px.bar(srv_counts, x="Service", y="Count", color="Service", text="Count", title="Top Application Services")
                        st.plotly_chart(style_chart(fig_srv), width="stretch")
                     else:
                        st.info("Service column ('service') not found in dataset.")

            with eda_t2:
                col_d1, col_d2 = st.columns(2)
                with col_d1:
                    if "state" in df_upload.columns:
                        state_counts = df_upload["state"].value_counts().head(8).reset_index()
                        state_counts.columns = ["State", "Count"]
                        fig_state = px.pie(state_counts, names="State", values="Count", hole=0.5, title="Connection Lifecycle States")
                        st.plotly_chart(style_chart(fig_state), width="stretch")
                    else:
                        st.info("State column ('state') not found in dataset.")
                with col_d2:
                    numeric_cols = [c for c in ["dur", "spkts", "dpkts", "sbytes", "dbytes", "rate"] if c in df_upload.columns]
                    if numeric_cols:
                        selected_metric = st.selectbox("Select Numerical Metric to Inspect Histogram", numeric_cols, index=0)
                        q99 = float(df_upload[selected_metric].quantile(0.99))
                        clipped_series = df_upload[selected_metric].clip(upper=q99)
                        fig_hist = px.histogram(clipped_series, nbins=30, title=f"Distribution of {selected_metric} (up to 99th percentile)")
                        st.plotly_chart(style_chart(fig_hist), width="stretch")
                    else:
                        st.info("No standard numerical flow metrics found.")

            with eda_t3:
                gt_col = None
                if "attack_cat" in df_upload.columns:
                    gt_col = "attack_cat"
                elif "label" in df_upload.columns:
                    gt_col = "label"

                if gt_col:
                    gt_counts = df_upload[gt_col].value_counts().reset_index()
                    gt_counts.columns = [gt_col, "Count"]
                    fig_gt = px.pie(gt_counts, names=gt_col, values="Count", hole=0.55, title=f"Ground Truth Distribution ({gt_col})")
                    st.plotly_chart(style_chart(fig_gt), width="stretch")
                else:
                    st.info("No ground-truth column ('label' or 'attack_cat') present in this uploaded dataset.")

            # RUN FULL BATCH INFERENCE
            if st.button("EXECUTE BATCH HYBRID AI INFERENCE ON DATASET", width="stretch"):
                with st.spinner("Processing dataset through Hybrid Random Forest, Isolation Forest & Multiclass Classifier..."):
                    classified_df = detect_network_traffic(df_upload)
                    st.session_state["uploaded_classified"] = classified_df
                    st.success(f"Batch AI Analysis Complete! Processed {len(classified_df):,} records.")

            if "uploaded_classified" in st.session_state:
                res_up = st.session_state["uploaded_classified"]

                r1, r2, r3, r4 = st.columns(4)
                r_attk = int((res_up["Final_Result"] == "Attack").sum())
                r_norm = int((res_up["Final_Result"] == "Normal").sum())
                r_crit = int((res_up["Risk_Level"] == "CRITICAL").sum())
                r_high = int((res_up["Risk_Level"] == "HIGH").sum())

                r1.metric("TOTAL ANALYZED", len(res_up))
                r2.metric("ATTACKS DETECTED", r_attk)
                r3.metric("NORMAL TRAFFIC", r_norm)
                r4.metric("HIGH / CRITICAL", r_crit + r_high)

                # Charts
                ch_left, ch_right = st.columns(2)
                with ch_left:
                    st.markdown("**Attack vs. Normal Distribution**")
                    fig_up_pie = px.pie(
                        res_up["Final_Result"].value_counts().reset_index(),
                        names="Final_Result",
                        values="count",
                        hole=0.6,
                        color="Final_Result",
                        color_discrete_map={"Attack": "#ed174c", "Normal": "#545462"}
                    )
                    st.plotly_chart(style_chart(fig_up_pie), width="stretch")

                with ch_right:
                    st.markdown("**Attack Categories Classified**")
                    if "Attack_Category" in res_up.columns:
                        cat_df = res_up["Attack_Category"].value_counts().reset_index()
                        cat_df.columns = ["Category", "Count"]
                        fig_up_cat = px.bar(cat_df, x="Category", y="Count", color="Category", text="Count")
                        st.plotly_chart(style_chart(fig_up_cat), width="stretch")

                st.markdown('<div class="section-title">DETECTION RESULTS TABLE</div>', unsafe_allow_html=True)
                filt_choice = st.selectbox("Filter Result Type", ["All", "Attack", "Normal", "CRITICAL Risk", "HIGH Risk"])
                show_df = res_up
                if filt_choice == "Attack":
                    show_df = res_up[res_up["Final_Result"] == "Attack"]
                elif filt_choice == "Normal":
                    show_df = res_up[res_up["Final_Result"] == "Normal"]
                elif filt_choice == "CRITICAL Risk":
                    show_df = res_up[res_up["Risk_Level"] == "CRITICAL"]
                elif filt_choice == "HIGH Risk":
                    show_df = res_up[res_up["Risk_Level"] == "HIGH"]

                st.dataframe(show_df.head(500), width="stretch", hide_index=True)

                csv_bytes, _ = generate_csv_report(res_up)
                st.download_button(
                    "DOWNLOAD CLASSIFIED DATASET CSV",
                    data=csv_bytes,
                    file_name="blackbox_classified_dataset.csv",
                    mime="text/csv",
                    width="stretch"
                )

        except Exception as e:
            st.error(f"Dataset Processing Error: {e}")
    else:
        st.info("Upload any CSV dataset containing network flow records to initiate AI threat analysis.")


# =====================================================
# 4. AI DETECTION ENGINE & EXPLAINABILITY (FEATURES 4, 5, 16)
# =====================================================

elif page == "AI Detection Engine":
    page_header(
        "04 / AI DETECTION ENGINE",
        "Hybrid Intelligence & AI Explainability",
        "Evaluate the Hybrid Random Forest + Isolation Forest models, inspect multiclass attack categories, and drill down into per-flow AI explanations."
    )

    if st.button("RUN FULL BENCHMARK DATASET DETECTION (82,332 RECORDS)", width="stretch"):
        run_full_detection.clear()
        with st.spinner("Analyzing testing records through hybrid pipeline..."):
            res = get_results()
            st.session_state["results_ready"] = True
            st.success(f"Benchmark analysis complete on {len(res):,} testing records.")

    if st.session_state.get("results_ready", True):
        res = get_results()

        st.markdown('<div class="section-title">BENCHMARK PERFORMANCE & MULTICLASS DETECTION BREAKDOWN</div>', unsafe_allow_html=True)
        bm1, bm2, bm3, bm4 = st.columns(4)
        bm_total = len(res)
        bm_attk = int((res["Final_Result"] == "Attack").sum())
        bm_norm = int((res["Final_Result"] == "Normal").sum())
        bm_crit = int((res["Risk_Level"] == "CRITICAL").sum())
        bm1.metric("BENCHMARK FLOWS", f"{bm_total:,}")
        bm2.metric("ATTACKS DETECTED", f"{bm_attk:,}")
        bm3.metric("ATTACK RATIO", f"{(bm_attk / max(1, bm_total))*100:.1f}%")
        bm4.metric("CRITICAL SEVERITY", f"{bm_crit:,}")

        c_left, c_right = st.columns(2)
        with c_left:
            st.markdown("**Attack vs. Normal Distribution**")
            fig_bm_pie = px.pie(
                res["Final_Result"].value_counts().reset_index(),
                names="Final_Result",
                values="count",
                hole=0.6,
                color="Final_Result",
                color_discrete_map={"Attack": "#ed174c", "Normal": "#545462"}
            )
            st.plotly_chart(style_chart(fig_bm_pie), width="stretch")
        with c_right:
            st.markdown("**Multiclass Attack Categories**")
            if "Attack_Category" in res.columns:
                cat_df = res["Attack_Category"].value_counts().reset_index()
                cat_df.columns = ["Category", "Count"]
                fig_bm_cat = px.bar(cat_df, x="Category", y="Count", color="Category", text="Count")
                st.plotly_chart(style_chart(fig_bm_cat), width="stretch")

        st.markdown('<div class="section-title">GLOBAL MODEL FEATURE IMPORTANCE (AI EXPLAINABILITY)</div>', unsafe_allow_html=True)
        explain_eng = AIExplainabilityEngine(model_type="benchmark")
        global_imp_df = explain_eng.get_global_importances()
        global_imp_df["Display_Label"] = global_imp_df.apply(
            lambda r: f"{r['Feature']} — {r['Description']}", axis=1
        )

        fig_imp = px.bar(
            global_imp_df.head(12),
            x="Importance",
            y="Display_Label",
            orientation="h",
            color="Importance",
            text="Importance",
            color_continuous_scale=["#33111b", "#ed174c"]
        )
        fig_imp.update_layout(yaxis=dict(autorange="reversed"), yaxis_title="Feature & Description")
        st.plotly_chart(style_chart(fig_imp), width="stretch")

        st.markdown('<div class="section-title">LOCAL (PER-FLOW) AI EXPLAINABILITY DRILL-DOWN</div>', unsafe_allow_html=True)
        exp_c1, exp_c2 = st.columns([1, 3])
        with exp_c1:
            query_id = st.number_input("Enter Traffic ID to Explain", min_value=1, max_value=len(res), value=1)
        with exp_c2:
            st.caption("Drills into the decision trees of the Random Forest to explain *why* the AI classified the specific flow.")

        if query_id <= len(res):
            flow_record = res.iloc[query_id - 1]
            flow_dict = flow_record.to_dict()
            explanation = explain_eng.explain_flow(flow_dict)

            f_col1, f_col2, f_col3, f_col4 = st.columns(4)
            f_col1.metric("FLOW VERDICT", f"{flow_record['Final_Result']}")
            f_col2.metric("ATTACK PROBABILITY", f"{flow_record['Attack_Probability']}%")
            f_col3.metric("ATTACK CATEGORY", f"{flow_record.get('Attack_Category', 'Unknown')}")
            f_col4.metric("COMPOSITE RISK", f"{flow_record['Risk_Score']} / 100 ({flow_record.get('Risk_Level', 'N/A')})")

            st.info(f"**Executive AI Verdict:** {explanation['Summary_Reason']}")

            exp_tab1, exp_tab2 = st.columns([3, 2])
            with exp_tab1:
                st.markdown("**Top Influential Decision-Path Features**")
                factors_df = pd.DataFrame(explanation["Top_Factors"])
                if not factors_df.empty:
                    factors_df = factors_df.rename(columns={
                        "Feature": "Feature Code",
                        "Description": "Plain-Language Name",
                        "Value": "Observed Value",
                        "Influence": "Tree Influence (%)"
                    })
                    st.dataframe(factors_df, width="stretch", hide_index=True)
            with exp_tab2:
                if explanation["Top_Factors"]:
                    top_f_df = pd.DataFrame(explanation["Top_Factors"])
                    fig_tf = px.bar(
                        top_f_df,
                        x="Influence",
                        y="Feature",
                        orientation="h",
                        color="Influence",
                        text="Influence",
                        color_continuous_scale=["#33111b", "#ed174c"],
                        title="Decision Tree Vote Contribution (%)"
                    )
                    fig_tf.update_layout(yaxis=dict(autorange="reversed"))
                    st.plotly_chart(style_chart(fig_tf), width="stretch")


# =====================================================
# 5. THREAT INTELLIGENCE HUB (FEATURES 9, 10, 13)
# =====================================================

elif page == "Threat Intelligence Hub":
    page_header(
        "05 / THREAT INTELLIGENCE",
        "IP Reputation & Entity Profiling",
        "Enrich suspicious IPs and domains against verified threat intelligence feeds and inspect host behavior profiles."
    )

    t_engine = ThreatIntelEngine()

    st.markdown('<div class="section-title">IP REPUTATION & THREAT LOOKUP</div>', unsafe_allow_html=True)
    c_ip, c_key, c_btn = st.columns([2, 2, 1])

    with c_ip:
        lookup_ip = st.text_input("IP Address to Investigate", value="185.220.101.5", placeholder="e.g. 194.26.29.42 or 8.8.8.8")
    with c_key:
        api_key_input = st.text_input("Optional AbuseIPDB API Key", type="password", placeholder="Leave blank to use local threat database")
    with c_btn:
        st.write("")
        st.write("")
        lookup_trigger = st.button("CHECK REPUTATION", width="stretch")

    if lookup_trigger or lookup_ip:
        rep_result = t_engine.lookup_ip(lookup_ip, abuseipdb_key=api_key_input)

        rc1, rc2, rc3, rc4 = st.columns(4)
        rc1.metric("HOST IP", rep_result["ip"])
        rc2.metric("REPUTATION SCORE", f"{rep_result['reputation_score']} / 100")
        rc3.metric("STATUS", rep_result["status"])
        rc4.metric("COUNTRY / ASN", f"{rep_result['country']} ({rep_result['asn']})")

        st.markdown(f"""
        **Threat Classification:** `{rep_result['threat_type']}`  
        **Attribution Source:** `{rep_result['source']}`  
        **Verified Evidence:** `{rep_result['details']}`  
        **Lookup Timestamp:** `{rep_result['last_checked']}`  
        """)

    # Host Profiling Section (Feature 10)
    st.markdown('<div class="section-title">HOST BEHAVIOUR PROFILING & THREAT POSTURE</div>', unsafe_allow_html=True)
    flows_sample = st.session_state.get("live_flow_summaries", [])
    if flows_sample:
        host_profiles_df = profile_network_hosts(pd.DataFrame(flows_sample))
        if not host_profiles_df.empty:
            st.dataframe(host_profiles_df, width="stretch", hide_index=True)
        else:
            st.info("No active hosts to profile.")
    else:
        st.info("Live network traffic flows are required to profile active network entities.")


# =====================================================
# 6. SOC ALERTS & INCIDENTS (FEATURES 11, 12, 15)
# =====================================================

elif page == "SOC Alerts & Incidents":
    page_header(
        "06 / SOC OPERATIONS",
        "Security Alert Center & Incident Investigation",
        "Manage real-time security alerts, correlate incident outbreak timelines, and track connection states."
    )

    tab_alerts, tab_incidents = st.tabs(["SECURITY ALERTS CENTER", "INCIDENT INVESTIGATION"])

    with tab_alerts:
        st.markdown('<div class="section-title">ACTIVE SECURITY ALERTS</div>', unsafe_allow_html=True)
        f_col1, f_col2 = st.columns(2)
        with f_col1:
            sev_filter = st.selectbox("Filter Alert Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        with f_col2:
            stat_filter = st.selectbox("Filter Alert Status", ["ALL", "NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"])

        alerts = soc_db.get_alerts(limit=100, status_filter=stat_filter, severity_filter=sev_filter)
        if alerts:
            alerts_df = pd.DataFrame(alerts)
            st.dataframe(
                alerts_df[["alert_id", "timestamp", "source_ip", "destination_ip", "protocol", "attack_category", "severity", "risk_score", "status", "detection_reason"]],
                width="stretch",
                hide_index=True
            )

            # Alert Status Transition Form
            st.markdown("### Update Alert Status")
            a_c1, a_c2, a_c3, a_c4 = st.columns([2, 2, 3, 1])
            with a_c1:
                target_alt = st.selectbox("Alert ID", [a["alert_id"] for a in alerts])
            with a_c2:
                new_alt_stat = st.selectbox("New Status", ["NEW", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"])
            with a_c3:
                notes = st.text_input("Analyst Remarks", placeholder="e.g. Confirmed benign scanner; rule updated.")
            with a_c4:
                st.write("")
                st.write("")
                if st.button("UPDATE", width="stretch"):
                    soc_db.update_alert_status(target_alt, new_alt_stat, notes)
                    st.success(f"Alert {target_alt} updated to {new_alt_stat}.")
                    st.rerun()
        else:
            st.info("No security alerts matching the selected filters.")

    with tab_incidents:
        st.markdown('<div class="section-title">INCIDENT INVESTIGATION CENTRE</div>', unsafe_allow_html=True)
        incidents = soc_db.get_incidents()
        if incidents:
            st.dataframe(pd.DataFrame(incidents), width="stretch", hide_index=True)
        else:
            st.info("No escalated security incidents on record.")


# =====================================================
# 7. THREAT ANALYTICS & TUNING (FEATURES 17, 18)
# =====================================================

elif page == "Threat Analytics & Tuning":
    page_header(
        "07 / ANALYTICS & TUNING",
        "False Positive Feedback & Historical Analytics",
        "Submit analyst triage feedback, analyze false positive trends, and model precision/recall thresholds."
    )

    t1, t2 = st.tabs(["FALSE POSITIVE ANALYSIS & ANALYST FEEDBACK", "HISTORICAL THREAT ANALYTICS"])

    with t1:
        st.markdown('<div class="section-title">LOG ANALYST VERDICT / FALSE POSITIVE FEEDBACK</div>', unsafe_allow_html=True)
        fb_c1, fb_c2, fb_c3 = st.columns(3)
        with fb_c1:
            fb_id = st.text_input("Traffic / Alert ID", placeholder="e.g. ALT-20261122-XXXX")
            fb_src = st.text_input("Source IP", placeholder="e.g. 10.92.239.127")
        with fb_c2:
            fb_pred = st.selectbox("Model Prediction", ["Attack", "Anomaly", "Normal"])
            fb_verdict = st.selectbox("Analyst Confirmed Verdict", ["FALSE_POSITIVE", "CONFIRMED_ATTACK", "SUSPICIOUS_PROBE"])
        with fb_c3:
            fb_reason = st.text_area("Triage Evidence", placeholder="e.g. Valid local DNS query to router gateway; rate and size normal.")

        if st.button("SUBMIT ANALYST FEEDBACK TO DATABASE", width="stretch"):
            if fb_id and fb_src:
                soc_db.record_feedback(fb_id, fb_src, "", fb_pred, fb_verdict, fb_reason)
                st.success("Analyst feedback recorded successfully in SQLite persistent storage.")
                st.rerun()
            else:
                st.warning("Please provide Traffic ID and Source IP.")

        st.markdown("### Analyst Feedback Audit History")
        feedbacks = soc_db.get_feedback_records()
        if feedbacks:
            st.dataframe(pd.DataFrame(feedbacks), width="stretch", hide_index=True)
        else:
            st.info("No analyst triage feedback recorded yet.")

    with t2:
        st.markdown('<div class="section-title">LONGITUDINAL THREAT TELEMETRY & ATTACK TRENDS</div>', unsafe_allow_html=True)
        # Snapshot sample
        snaps = soc_db.get_historical_snapshots()
        if snaps:
            st.dataframe(pd.DataFrame(snaps), width="stretch", hide_index=True)
        else:
            st.info("Historical snapshots are collected periodically during live monitoring and batch inspections.")


# =====================================================
# 8. AUTOMATED SECURITY REPORTS (FEATURE 19)
# =====================================================

elif page == "Automated Security Reports":
    page_header(
        "08 / REPORTS",
        "Automated Security Reporting Hub",
        "Compile executive incident reports in PDF and raw CSV formats for SOC stakeholders and compliance audits."
    )

    # LIVE CAPTURE REPORT — uses only the current session's archived live evidence.
    live_flow_count = len(st.session_state.live_flow_history)
    live_detection_count = len(st.session_state.live_detection_history)
    live_meta = st.session_state.live_session_metadata

    st.markdown('<div class="section-title">LIVE NETWORK MONITORING REPORT (CAPTURED TRAFFIC)</div>', unsafe_allow_html=True)
    lm1, lm2, lm3, lm4 = st.columns(4)
    lm1.metric("LIVE PACKETS CAPTURED", f"{st.session_state.live_capture_stats.get('packet_count', 0):,}")
    lm2.metric("ARCHIVED LIVE FLOWS", f"{live_flow_count:,}")
    lm3.metric("LIVE DETECTION RECORDS", f"{live_detection_count:,}")
    lm4.metric("SESSION STATUS", str(live_meta.get("status", "NOT STARTED")))

    if live_meta.get("start_time"):
        st.caption(
            f"Interface: {live_meta.get('interface') or 'N/A'} | "
            f"Started: {live_meta.get('start_time')} | "
            f"Ended: {live_meta.get('end_time') or 'Session not yet stopped'}"
        )
    else:
        st.info("No live monitoring session has been started in this app session. Start capture from Network Monitoring to collect evidence.")

    if st.button(
        "GENERATE LIVE MONITORING PDF REPORT",
        width="stretch",
        disabled=(live_flow_count == 0 and st.session_state.live_capture_stats.get("packet_count", 0) == 0)
    ):
        with st.spinner("Building PDF from archived live capture evidence..."):
            st.session_state["live_monitoring_pdf_bytes"] = generate_live_monitoring_pdf()
        st.success("Live Monitoring PDF generated from captured session data.")

    if "live_monitoring_pdf_bytes" in st.session_state:
        st.download_button(
            "DOWNLOAD LIVE MONITORING PDF",
            data=st.session_state["live_monitoring_pdf_bytes"],
            file_name="BLACKBOX_Live_Monitoring_Report.pdf",
            mime="application/pdf",
            width="stretch"
        )

    st.markdown("---")

    rep_results = get_results()
    total_f = len(rep_results)
    attk_f = int((rep_results["Final_Result"] == "Attack").sum())
    anom_f = int((rep_results["Anomaly_Detection"] == "Anomaly").sum())
    crit_f = int((rep_results["Risk_Level"] == "CRITICAL").sum())
    high_f = int((rep_results["Risk_Level"] == "HIGH").sum())

    st.markdown('<div class="section-title">REPORT SUMMARY PREVIEW</div>', unsafe_allow_html=True)
    rp1, rp2, rp3, rp4 = st.columns(4)
    rp1.metric("TOTAL AUDITED FLOWS", f"{total_f:,}")
    rp2.metric("ATTACKS DETECTED", f"{attk_f:,}")
    rp3.metric("CRITICAL / HIGH", crit_f + high_f)
    rp4.metric("REPORT FORMATS", "PDF & CSV Ready")

    notes_input = st.text_area(
        "Executive Notes / Analyst Remarks (Included in PDF)",
        value="Inspection completed using BLACKBOX Hybrid Detection Engine. All critical alerts require immediate host isolation."
    )

    col_pdf, col_csv = st.columns(2)

    with col_pdf:
        if st.button("COMPILE EXECUTIVE SOC PDF REPORT", width="stretch"):
            with st.spinner("Generating styled multi-page PDF report..."):
                metrics = {
                    "total_flows": total_f,
                    "attacks": attk_f,
                    "anomalies": anom_f,
                    "critical_alerts": crit_f,
                    "high_alerts": high_f,
                }
                attk_counts = rep_results["Final_Result"].value_counts().reset_index()
                attk_counts.columns = ["Category", "Count"]

                crit_sample = rep_results[rep_results["Risk_Level"].isin(["CRITICAL", "HIGH"])].head(15)

                pdf_data = generate_pdf_report(
                    summary_metrics=metrics,
                    attack_breakdown_df=attk_counts,
                    critical_alerts_df=crit_sample,
                    executive_notes=notes_input
                )
                st.session_state["pdf_report_bytes"] = pdf_data
                st.success("PDF Report compiled successfully!")

        if "pdf_report_bytes" in st.session_state:
            st.download_button(
                "DOWNLOAD EXECUTIVE PDF REPORT",
                data=st.session_state["pdf_report_bytes"],
                file_name="BLACKBOX_Executive_Security_Report.pdf",
                mime="application/pdf",
                width="stretch"
            )

    with col_csv:
        csv_bytes, path_str = generate_csv_report(rep_results)
        st.download_button(
            "DOWNLOAD COMPLETE CSV DETECTION REPORT",
            data=csv_bytes,
            file_name="blackbox_incident_report.csv",
            mime="text/csv",
            width="stretch"
        )
        st.caption(f"Persistent CSV report automatically saved to: `{path_str}`")


# =====================================================
# FOOTER
# =====================================================

st.markdown("""
<div class="footer">
    <span>BLACKBOX</span> / NIDS &nbsp; — &nbsp;
    AI-POWERED NETWORK INTRUSION DETECTION & THREAT INTELLIGENCE PLATFORM
</div>
""", unsafe_allow_html=True)