import pandas as pd


CRITICAL_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    443: "HTTPS",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
}


def calculate_composite_risk_score(
    attack_probability,
    is_anomaly=False,
    attack_category="Normal",
    dest_port=0,
    packet_rate=0.0,
    behavior_threats=None,
    threat_intel_score=0
):
    """Calculates a normalized 0-100 Attack Risk Score incorporating AI probability,

    anomaly detection, port criticality, attack categorization, and behavioral indicators.
    
    Returns:
        tuple (score: int 0-100, level: str 'LOW'|'MEDIUM'|'HIGH'|'CRITICAL', factors: list)
    """
    prob = float(attack_probability) if attack_probability is not None else 0.0
    if prob > 1.0:
        prob = prob / 100.0  # Normalize percentage to 0.0-1.0

    score = 0.0
    factors = []

    # Factor 1: AI Model Probability (up to 45 pts)
    model_pts = prob * 45.0
    score += model_pts
    if prob >= 0.70:
        factors.append(f"AI Model Confidence ({prob * 100:.1f}%)")

    # Factor 2: Isolation Forest Anomaly (up to 15 pts)
    if is_anomaly:
        score += 15.0
        factors.append("Statistical Anomaly Flagged")

    # Factor 3: Attack Category Severity (up to 15 pts)
    cat_upper = str(attack_category).upper()
    if cat_upper in ("CRITICAL", "BACKDOOR", "SHELLCODE", "WORMS"):
        score += 15.0
        factors.append(f"Critical Attack Class ({attack_category})")
    elif cat_upper in ("EXPLOITS", "DOS", "RECONNAISSANCE"):
        score += 10.0
        factors.append(f"Severe Attack Class ({attack_category})")
    elif cat_upper in ("GENERIC", "FUZZERS", "ANALYSIS"):
        score += 5.0
        factors.append(f"Suspicious Class ({attack_category})")

    # Factor 4: Sensitive / Authentication Port Target (up to 10 pts)
    port = int(dest_port) if dest_port else 0
    if port in (21, 22, 23, 445, 3389, 3306, 5432, 5900):
        score += 10.0
        factors.append(f"Auth/Admin Service Target (Port {port}: {CRITICAL_PORTS.get(port, '')})")
    elif port in CRITICAL_PORTS:
        score += 5.0
        factors.append(f"Infrastructure Service Target (Port {port})")

    # Factor 5: Rate & Volume Anomalies (up to 8 pts)
    rate = float(packet_rate) if packet_rate is not None else 0.0
    if rate > 500.0:
        score += 8.0
        factors.append(f"High-frequency packet burst ({rate:.1f} pkts/s)")
    elif rate > 100.0:
        score += 4.0
        factors.append("Elevated packet transmission rate")

    # Factor 6: Heuristic Threat Behaviors (up to 7 pts)
    if behavior_threats:
        score += min(len(behavior_threats) * 4.0, 7.0)
        factors.append(f"Behavioral Patterns ({', '.join(behavior_threats[:2])})")

    # Factor 7: Threat Intelligence Reputation (bonus up to 10 pts)
    if threat_intel_score > 0:
        ti_pts = min(threat_intel_score * 0.1, 10.0)
        score += ti_pts
        factors.append(f"Threat Intelligence Reputation Score ({threat_intel_score}/100)")

    final_score = int(min(max(round(score), 0), 100))

    if final_score >= 80:
        level = "CRITICAL"
    elif final_score >= 60:
        level = "HIGH"
    elif final_score >= 35:
        level = "MEDIUM"
    else:
        level = "LOW"

    return final_score, level, factors
