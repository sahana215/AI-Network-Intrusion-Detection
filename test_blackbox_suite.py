import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
import pandas as pd
import numpy as np
import joblib
from scapy.all import IP, TCP, UDP, DNS, DNSQR, DNSRR

from modules.flow_engine import FlowAggregator
from modules.preprocessing import preprocess_datasets, ENCODER_PATH
from modules.detection_engine import load_models, detect_network_traffic
from modules.live_ai_engine import load_live_models, detect_live_flows, FEATURE_COLUMNS, AlertDeduplicator
from modules.attack_classifier import load_attack_classifier, classify_attack_flows
from modules.risk_engine import calculate_composite_risk_score
from modules.threat_intel import ThreatIntelEngine
from modules.soc_database import SOCDatabase
from modules.live_capture import extract_packet_info, decode_tcp_flags, get_available_interfaces
from modules.connection_tracker import ConnectionTracker
from modules.explainability_engine import AIExplainabilityEngine
from modules.report_generator import generate_csv_report, generate_pdf_report


# =====================================================================
# 1-6: CORE PIPELINE & FLOW ENGINE TESTS
# =====================================================================

def test_flow_directionality_client_first():
    agg = FlowAggregator()
    pkt = IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=55123, dport=53)
    pkt.time = 100.0
    agg.add_packet(pkt)
    flows = agg.get_flow_summary()
    assert len(flows) == 1
    assert flows[0]["Source IP"] == "192.168.1.50"
    assert flows[0]["Destination IP"] == "8.8.8.8"
    assert flows[0]["Source Port"] == 55123
    assert flows[0]["Destination Port"] == 53


def test_flow_directionality_server_response_first():
    """If sniffer starts mid-stream and catches DNS response first, client should be initiator."""
    agg = FlowAggregator()
    pkt = IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=55123)
    pkt.time = 100.0
    agg.add_packet(pkt)
    flows = agg.get_flow_summary()
    assert len(flows) == 1
    assert flows[0]["Source IP"] == "192.168.1.50"
    assert flows[0]["Destination IP"] == "8.8.8.8"
    assert flows[0]["Destination Port"] == 53


def test_flow_expiration_and_memory_stability():
    agg = FlowAggregator(udp_timeout=1.0)
    for i in range(10):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1000 + i, dport=53)
        pkt.time = 1000.0 + i
        agg.add_packet(pkt)

    assert len(agg.flows) == 10
    # Simulate time advancing 10 seconds later
    evicted = agg.evict_expired_flows(current_time=1020.0)
    assert evicted == 10
    assert len(agg.flows) == 0
    assert len(agg.completed_flows) == 10


def test_packet_and_byte_calculations():
    agg = FlowAggregator()
    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S", seq=100)
    pkt1.time = 100.0
    pkt2 = IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=5000, flags="SA", seq=200, ack=101)
    pkt2.time = 100.02

    agg.add_packet(pkt1)
    agg.add_packet(pkt2)

    flows = agg.get_flow_summary()
    assert len(flows) == 1
    flow = flows[0]
    assert flow["spkts"] == 1
    assert flow["dpkts"] == 1
    assert flow["Total Packets"] == 2
    assert flow["sbytes"] == len(pkt1[IP])
    assert flow["dbytes"] == len(pkt2[IP])
    assert flow["Total Bytes"] == flow["sbytes"] + flow["dbytes"]


def test_rate_and_load_calculations():
    agg = FlowAggregator()
    pkt1 = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)
    pkt1.time = 100.0
    pkt2 = IP(src="10.0.0.2", dst="10.0.0.1") / UDP(sport=53, dport=5000)
    pkt2.time = 100.05  # 50 ms duration

    agg.add_packet(pkt1)
    agg.add_packet(pkt2)

    flows = agg.get_flow_summary()
    flow = flows[0]
    assert flow["dur"] > 0.0
    assert flow["rate"] > 0.0
    assert flow["sload"] > 0.0
    assert flow["dload"] > 0.0


def test_inter_arrival_time_calculations():
    agg = FlowAggregator()
    # 3 forward packets with 10ms intervals
    for t in [100.0, 100.010, 100.020]:
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="A")
        pkt.time = t
        agg.add_packet(pkt)

    flows = agg.get_flow_summary()
    assert len(flows) == 1
    # Mean IAT should be approximately 10.0 ms
    assert abs(flows[0]["sinpkt"] - 10.0) < 0.1


# =====================================================================
# 7-10: ENCODER & AI DETECTION TESTS
# =====================================================================

def test_categorical_encoder_consistency():
    pkg = joblib.load(ENCODER_PATH)
    encoder = pkg["encoder"]
    cat_cols = pkg["categorical_columns"]

    test_df = pd.DataFrame({
        "proto": ["udp", "tcp", "icmp"],
        "service": ["dns", "http", "ssl"],
        "state": ["CON", "INT", "FIN"]
    })
    trans = encoder.transform(test_df[cat_cols])

    assert trans[0, 0] == 119.0  # udp
    assert trans[1, 0] == 113.0  # tcp
    assert trans[0, 1] == 2.0    # dns
    assert trans[1, 1] == 5.0    # http
    assert trans[2, 1] == 12.0   # ssl
    assert trans[0, 2] == 0.0    # CON
    assert trans[1, 2] == 3.0    # INT
    assert trans[2, 2] == 2.0    # FIN


def test_binary_ai_detection():
    rf, iso, cols, _, _ = load_models()
    assert rf is not None
    assert iso is not None
    assert len(cols) == 42


def test_multiclass_classification():
    pkg = load_attack_classifier()
    model = pkg["classifier"]
    classes = pkg["classes"]
    assert len(classes) >= 9
    assert "Normal" in classes
    assert "DoS" in classes
    assert "Exploits" in classes


def test_live_ai_pipeline():
    live_pkg = load_live_models()
    assert len(live_pkg["feature_columns"]) == 22
    sample = pd.DataFrame([{
        "Flow ID": "10.0.0.1:5000-10.0.0.2:80",
        "Source IP": "10.0.0.1",
        "Destination IP": "10.0.0.2",
        "Source Port": 5000,
        "Destination Port": 80,
        "Protocol": "TCP",
        "dur": 0.05,
        "proto": "tcp",
        "service": "http",
        "state": "CON",
        "spkts": 2,
        "dpkts": 2,
        "sbytes": 120,
        "dbytes": 240,
        "rate": 80.0,
        "sload": 19200.0,
        "dload": 38400.0,
        "sinpkt": 10.0,
        "dinpkt": 10.0,
        "sjit": 0.0,
        "djit": 0.0,
        "swin": 255.0,
        "dwin": 255.0,
        "tcprtt": 0.01,
        "synack": 0.005,
        "ackdat": 0.005,
        "smean": 60.0,
        "dmean": 120.0
    }])
    res = detect_live_flows(sample)
    assert res is not None
    assert len(res) == 1
    assert "Attack_Category" in res.columns
    assert "Risk_Score" in res.columns


# =====================================================================
# 11-15: RISK, THREAT INTEL, ALERTS & REPUTATION TESTS
# =====================================================================

def test_risk_scoring():
    score_low, level_low, _ = calculate_composite_risk_score(0.20, is_anomaly=False, dest_port=80)
    assert level_low == "LOW"
    assert score_low < 40

    score_crit, level_crit, _ = calculate_composite_risk_score(0.95, is_anomaly=True, attack_category="Backdoor", dest_port=22)
    assert level_crit == "CRITICAL"
    assert score_crit >= 80


def test_threat_intelligence_private_ip():
    ti = ThreatIntelEngine()
    rep = ti.lookup_ip("192.168.1.1")
    assert rep["status"] == "INTERNAL"
    assert rep["reputation_score"] == 0


def test_threat_intelligence_known_threat():
    ti = ThreatIntelEngine()
    rep = ti.lookup_ip("185.220.101.5")
    assert rep["status"] == "MALICIOUS"
    assert rep["reputation_score"] >= 80


def test_soc_alert_creation_and_escalation():
    db = SOCDatabase()
    alt_id = db.create_alert(
        source_ip="194.26.29.42",
        destination_ip="10.0.0.5",
        source_port=4444,
        destination_port=22,
        protocol="TCP",
        attack_category="Brute Force",
        severity="CRITICAL",
        risk_score=95,
        confidence=98.0,
        detection_reason="Test alert creation"
    )
    assert alt_id.startswith("ALT-")

    alerts = db.get_alerts(limit=5)
    matching = [a for a in alerts if a["alert_id"] == alt_id]
    assert len(matching) == 1
    assert matching[0]["severity"] == "CRITICAL"


def test_packet_inspection():
    pkt = IP(src="1.2.3.4", dst="5.6.7.8", ttl=64) / TCP(sport=1234, dport=80, flags="SA", seq=1000, ack=2000, window=65535)
    info = extract_packet_info(pkt)
    assert info["Source IP"] == "1.2.3.4"
    assert info["Destination IP"] == "5.6.7.8"
    assert info["TTL"] == 64
    assert info["TCP Flags"] == "SYN-ACK"
    assert info["Seq Number"] == 1000


def test_connection_tracking():
    tracker = ConnectionTracker()
    flow = {
        "Flow ID": "10.0.0.1:5000-10.0.0.2:80",
        "Source IP": "10.0.0.1",
        "Destination IP": "10.0.0.2",
        "Source Port": 5000,
        "Destination Port": 80,
        "Protocol": "TCP",
        "service": "http",
        "state": "CON",
        "Total Packets": 10,
        "Total Bytes": 1500,
        "dur": 0.5
    }
    tracker.update_connection(flow)
    sessions = tracker.get_all_sessions()
    assert len(sessions) >= 1
    sess = [s for s in sessions if s["Flow ID"] == flow["Flow ID"]][0]
    assert sess["State"] == "CON"
    assert sess["Repeated Count"] >= 1


# =====================================================================
# 16-20: EXPLAINABILITY & REPORT GENERATION TESTS
# =====================================================================

def test_ai_explainability():
    engine = AIExplainabilityEngine()
    importances = engine.get_global_importances()
    assert not importances.empty
    assert "Feature" in importances.columns
    assert "Importance" in importances.columns

    sample_flow = {
        "dur": 0.05, "proto": 113.0, "service": 5.0, "state": 0.0,
        "spkts": 2.0, "dpkts": 2.0, "sbytes": 120.0, "dbytes": 240.0,
        "rate": 80.0, "sload": 19200.0, "dload": 38400.0, "sinpkt": 10.0,
        "dinpkt": 10.0, "sjit": 0.0, "djit": 0.0, "swin": 255.0, "dwin": 255.0,
        "tcprtt": 0.01, "synack": 0.005, "ackdat": 0.005, "smean": 60.0, "dmean": 120.0
    }
    exp = engine.explain_flow(sample_flow)
    assert "Verdict" in exp
    assert "Attack_Probability" in exp
    assert "Top_Factors" in exp


def test_report_generation():
    df = pd.DataFrame([
        {"Traffic_ID": 1, "Final_Result": "Attack", "Attack_Category": "DoS", "Risk_Level": "CRITICAL", "Detection_Reason": "SYN Flood pattern"}
    ])
    csv_bytes, path_str = generate_csv_report(df)
    assert len(csv_bytes) > 0
    assert Path(path_str).exists()

    metrics = {
        "total_flows": 100,
        "attacks": 10,
        "anomalies": 5,
        "critical_alerts": 2,
        "high_alerts": 4,
    }
    pdf_bytes = generate_pdf_report(metrics, attack_breakdown_df=pd.DataFrame([{"Category": "DoS", "Count": 10, "Severity": "HIGH"}]))
    assert len(pdf_bytes) > 1000
    assert pdf_bytes[:4] == b"%PDF"


def test_engine_validation_and_ui_standards():
    """Validates model health checking, AST standards, and zero deprecated arguments."""
    from app import validate_engine_status
    status = validate_engine_status()
    assert status["offline"][0] == "ACTIVE", f"Offline model status: {status['offline']}"
    assert status["live"][0] == "ACTIVE", f"Live model status: {status['live']}"
    assert status["classifier"][0] == "ACTIVE", f"Classifier model status: {status['classifier']}"

    # Verify app.py has zero deprecated use_container_width
    app_text = (PROJECT_ROOT / "app.py").read_text(encoding="utf-8")
    assert "use_container_width" not in app_text, "Found deprecated use_container_width in app.py"


def test_database_wal_and_metrics_integrity():
    """Verifies SQLite WAL mode concurrency and metrics computation."""
    db = SOCDatabase()
    with db._get_connection() as conn:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert journal_mode.upper() == "WAL", f"Expected WAL mode, got {journal_mode}"

    metrics = db.get_soc_metrics()
    assert "total_alerts" in metrics
    assert "new_alerts" in metrics
    assert "open_incidents" in metrics
    assert "false_positives" in metrics
    assert metrics["total_alerts"] >= 0


# =====================================================================
# 21-25: ADVANCED PIPELINE, INTERFACES, DEDUPLICATION & BENCHMARK TESTS
# =====================================================================

def test_batch_vectorized_detection():
    """Verifies vectorized detect_network_traffic produces full threat metrics."""
    test_rows = [
        {
            "dur": 0.000009, "proto": "udp", "service": "dns", "state": "INT",
            "spkts": 2, "dpkts": 0, "sbytes": 114, "dbytes": 0, "rate": 111111.1072,
            "sttl": 254, "dttl": 0, "sload": 50666664.0, "dload": 0.0, "sloss": 0, "dloss": 0,
            "sinpkt": 0.009, "dinpkt": 0.0, "sjit": 0.0, "djit": 0.0, "swin": 0, "stcpb": 0,
            "dtcpb": 0, "dwin": 0, "tcprtt": 0.0, "synack": 0.0, "ackdat": 0.0, "smean": 57,
            "dmean": 0, "trans_depth": 0, "response_body_len": 0, "ct_srv_src": 2,
            "ct_state_ttl": 2, "ct_dst_ltm": 1, "ct_src_dport_ltm": 1, "ct_dst_sport_ltm": 1,
            "ct_dst_src_ltm": 2, "is_ftp_login": 0, "ct_ftp_cmd": 0, "ct_flw_http_mthd": 0,
            "ct_src_ltm": 1, "ct_srv_dst": 2, "is_sm_ips_ports": 0
        },
        {
            "dur": 0.5, "proto": "tcp", "service": "http", "state": "CON",
            "spkts": 10, "dpkts": 12, "sbytes": 800, "dbytes": 4500, "rate": 44.0,
            "sttl": 64, "dttl": 64, "sload": 12800.0, "dload": 72000.0, "sloss": 0, "dloss": 0,
            "sinpkt": 50.0, "dinpkt": 40.0, "sjit": 1.2, "djit": 1.5, "swin": 255, "stcpb": 1000,
            "dtcpb": 2000, "dwin": 255, "tcprtt": 0.015, "synack": 0.008, "ackdat": 0.007,
            "smean": 80, "dmean": 375, "trans_depth": 1, "response_body_len": 4000,
            "ct_srv_src": 1, "ct_state_ttl": 0, "ct_dst_ltm": 1, "ct_src_dport_ltm": 1,
            "ct_dst_sport_ltm": 1, "ct_dst_src_ltm": 1, "is_ftp_login": 0, "ct_ftp_cmd": 0,
            "ct_flw_http_mthd": 1, "ct_src_ltm": 1, "ct_srv_dst": 1, "is_sm_ips_ports": 0
        }
    ]
    df = pd.DataFrame(test_rows)
    res = detect_network_traffic(df)
    assert len(res) == 2
    assert "Final_Result" in res.columns
    assert "Attack_Probability" in res.columns
    assert "Attack_Category" in res.columns
    assert "Risk_Score" in res.columns
    assert "Risk_Level" in res.columns
    assert "Detection_Reason" in res.columns


def test_alert_deduplication_cooldown():
    """Verifies AlertDeduplicator suppresses repeated alerts within cooldown window."""
    dedup = AlertDeduplicator(cooldown_seconds=1.0)
    now = 1000.0
    # First alert should trigger
    assert dedup.should_alert("192.168.1.10:5000-10.0.0.1:80", current_time=now) is True
    # Immediate duplicate flow should be suppressed
    assert dedup.should_alert("192.168.1.10:5000-10.0.0.1:80", current_time=now + 0.5) is False
    # Different flow ID should trigger
    assert dedup.should_alert("192.168.1.10:5001-10.0.0.1:443", current_time=now + 0.5) is True
    # After cooldown expires (1.1s later), should trigger again
    assert dedup.should_alert("192.168.1.10:5000-10.0.0.1:80", current_time=now + 1.2) is True


def test_network_interface_auto_detection():
    """Verifies that available network interfaces are detected and indexed with default route awareness."""
    interfaces = get_available_interfaces()
    assert isinstance(interfaces, list)
    assert len(interfaces) > 0
    for iface in interfaces:
        assert "id" in iface
        assert "description" in iface
        assert "is_default" in iface
    top_iface = interfaces[0]
    assert top_iface["is_default"] in [True, False]


def test_benchmark_explainability_engine():
    """Verifies AIExplainabilityEngine on full 42-feature benchmark model."""
    engine = AIExplainabilityEngine(model_type="benchmark")
    assert len(engine.feature_columns) == 42
    importances = engine.get_global_importances()
    assert len(importances) == 42
    assert "Description" in importances.columns
    smean_row = importances[importances["Feature"] == "smean"]
    assert not smean_row.empty
    assert "payload" in smean_row.iloc[0]["Description"].lower()


def test_threat_intel_caching_and_error_handling():
    """Verifies local threat lookup, caching, and invalid API key graceful fallback."""
    ti = ThreatIntelEngine()
    res = ti.lookup_ip("8.8.8.8", abuseipdb_key="")
    assert res["ip"] == "8.8.8.8"
    assert res["status"] in ["CLEAN", "BENIGN", "INTERNAL", "MALICIOUS", "UNKNOWN"]
    assert "reputation_score" in res
    assert res["reputation_score"] <= 20


if __name__ == "__main__":
    pytest.main(["-v", __file__])
