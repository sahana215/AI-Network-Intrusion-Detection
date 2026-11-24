import json
import logging
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOC_DB_PATH = PROJECT_ROOT / "database" / "blackbox_soc.db"

logger = logging.getLogger("BLACKBOX.SOCDatabase")


class SOCDatabase:
    """Manages persistent SQLite storage for BLACKBOX SOC alerts, incidents,

    analyst feedback, and historical telemetry.
    """

    def __init__(self, db_path=SOC_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        return conn

    def _initialize_schema(self):
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS security_alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    source_ip TEXT,
                    destination_ip TEXT,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT,
                    attack_category TEXT,
                    severity TEXT,
                    risk_score INTEGER,
                    confidence REAL,
                    detection_reason TEXT,
                    evidence_json TEXT,
                    status TEXT DEFAULT 'NEW',
                    analyst_notes TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS security_incidents (
                    incident_id TEXT PRIMARY KEY,
                    title TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    severity TEXT,
                    status TEXT DEFAULT 'OPEN',
                    primary_host TEXT,
                    attack_type TEXT,
                    alert_count INTEGER DEFAULT 1,
                    summary TEXT,
                    analyst_notes TEXT DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS analyst_feedback (
                    feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    traffic_id TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    predicted_label TEXT,
                    analyst_verdict TEXT,
                    reason TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS historical_traffic_snapshots (
                    snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_flows INTEGER,
                    attack_flows INTEGER,
                    anomaly_flows INTEGER,
                    critical_alerts INTEGER,
                    high_alerts INTEGER,
                    top_attack_class TEXT
                );
            """)
            conn.commit()

    # ------------------ ALERTS MANAGEMENT ------------------

    def create_alert(
        self,
        source_ip,
        destination_ip,
        source_port=0,
        destination_port=0,
        protocol="TCP",
        attack_category="Suspicious Activity",
        severity="HIGH",
        risk_score=75,
        confidence=85.0,
        detection_reason="",
        evidence=None,
        status="NEW"
    ):
        alert_id = f"ALT-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        evidence_str = json.dumps(evidence or {})

        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO security_alerts (
                    alert_id, source_ip, destination_ip, source_port, destination_port,
                    protocol, attack_category, severity, risk_score, confidence,
                    detection_reason, evidence_json, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert_id, str(source_ip), str(destination_ip), int(source_port or 0),
                int(destination_port or 0), str(protocol).upper(), str(attack_category),
                str(severity).upper(), int(risk_score), float(confidence),
                str(detection_reason), evidence_str, str(status).upper()
            ))
            conn.commit()

        # Correlate into incident if high or critical severity
        if severity in ("HIGH", "CRITICAL"):
            self._correlate_incident_from_alert(alert_id, source_ip, attack_category, severity, detection_reason)

        return alert_id

    def get_alerts(self, limit=200, status_filter=None, severity_filter=None):
        query = "SELECT * FROM security_alerts WHERE 1=1"
        params = []

        if status_filter and status_filter != "ALL":
            query += " AND status = ?"
            params.append(status_filter)

        if severity_filter and severity_filter != "ALL":
            query += " AND severity = ?"
            params.append(severity_filter)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def update_alert_status(self, alert_id, new_status, notes=""):
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE security_alerts
                SET status = ?, analyst_notes = ?
                WHERE alert_id = ?
            """, (new_status.upper(), notes, alert_id))
            conn.commit()

    # ------------------ INCIDENT INVESTIGATION ------------------

    def _correlate_incident_from_alert(self, alert_id, source_ip, attack_type, severity, reason):
        with self._get_connection() as conn:
            existing = conn.execute("""
                SELECT incident_id, alert_count FROM security_incidents
                WHERE primary_host = ? AND status != 'CLOSED'
                ORDER BY updated_at DESC LIMIT 1
            """, (source_ip,)).fetchone()

            if existing:
                incident_id = existing["incident_id"]
                conn.execute("""
                    UPDATE security_incidents
                    SET alert_count = alert_count + 1, updated_at = CURRENT_TIMESTAMP
                    WHERE incident_id = ?
                """, (incident_id,))
            else:
                incident_id = f"INC-{datetime.now().strftime('%Y%m')}-{uuid.uuid4().hex[:4].upper()}"
                title = f"{attack_type} Outbreak from {source_ip}"
                summary = f"Multiple high-severity alerts detected from host {source_ip}. Initial detection: {reason}."
                conn.execute("""
                    INSERT INTO security_incidents (
                        incident_id, title, severity, primary_host, attack_type, alert_count, summary
                    ) VALUES (?, ?, ?, ?, ?, 1, ?)
                """, (incident_id, title, severity, source_ip, attack_type, summary))

            conn.commit()

    def get_incidents(self, limit=50):
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM security_incidents
                ORDER BY updated_at DESC LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]

    def update_incident_status(self, incident_id, new_status, notes=""):
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE security_incidents
                SET status = ?, analyst_notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE incident_id = ?
            """, (new_status.upper(), notes, incident_id))
            conn.commit()

    # ------------------ ANALYST FEEDBACK (FALSE POSITIVE TRACKING) ------------------

    def record_feedback(self, traffic_id, source_ip, destination_ip, predicted_label, analyst_verdict, reason=""):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO analyst_feedback (
                    traffic_id, source_ip, destination_ip, predicted_label, analyst_verdict, reason
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (str(traffic_id), str(source_ip), str(destination_ip), str(predicted_label), str(analyst_verdict), str(reason)))
            conn.commit()

    def get_feedback_records(self, limit=100):
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM analyst_feedback
                ORDER BY created_at DESC LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]

    # ------------------ HISTORICAL TELEMETRY ------------------

    def record_traffic_snapshot(self, total_flows, attack_flows, anomaly_flows, critical_alerts, high_alerts, top_class):
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO historical_traffic_snapshots (
                    total_flows, attack_flows, anomaly_flows, critical_alerts, high_alerts, top_attack_class
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (int(total_flows), int(attack_flows), int(anomaly_flows), int(critical_alerts), int(high_alerts), str(top_class)))
            conn.commit()

    def get_historical_snapshots(self, limit=50):
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM historical_traffic_snapshots
                ORDER BY timestamp ASC LIMIT ?
            """, (limit,)).fetchall()
            return [dict(r) for r in rows]

    def get_soc_metrics(self):
        try:
            with self._get_connection() as conn:
                total_alerts = conn.execute("SELECT COUNT(*) FROM security_alerts").fetchone()[0]
                new_alerts = conn.execute("SELECT COUNT(*) FROM security_alerts WHERE status = 'NEW'").fetchone()[0]
                open_incidents = conn.execute("SELECT COUNT(*) FROM security_incidents WHERE status != 'CLOSED'").fetchone()[0]
                false_positives = conn.execute("SELECT COUNT(*) FROM analyst_feedback WHERE analyst_verdict = 'FALSE_POSITIVE'").fetchone()[0]
                return {
                    "total_alerts": total_alerts,
                    "new_alerts": new_alerts,
                    "open_incidents": open_incidents,
                    "false_positives": false_positives
                }
        except sqlite3.Error as e:
            logger.error(f"SQLite concurrent access error in get_soc_metrics: {e}", exc_info=True)
            raise
