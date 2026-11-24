import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd

FEATURE_DESCRIPTIONS = {
    "sload": "Source throughput rate (bits/second)",
    "dload": "Destination throughput rate (bits/second)",
    "rate": "Overall packet transmission rate (packets/second)",
    "ackdat": "TCP handshake acknowledgment response time",
    "dmean": "Average destination packet payload size",
    "smean": "Average source packet payload size",
    "tcprtt": "TCP round-trip time (SYNACK + ACKDAT)",
    "sbytes": "Total bytes transmitted by source host",
    "dbytes": "Total bytes transmitted by destination host",
    "synack": "TCP SYN to SYN-ACK handshake round-trip latency",
    "sinpkt": "Source inter-packet arrival time",
    "dinpkt": "Destination inter-packet arrival time",
    "dur": "Total flow duration",
    "spkts": "Total packets transmitted by source",
    "dpkts": "Total packets received from destination",
    "sjit": "Source packet jitter (inter-arrival variance)",
    "djit": "Destination packet jitter",
    "swin": "Source TCP window size advertisement",
    "dwin": "Destination TCP window size advertisement",
    "sttl": "Source IP Time-To-Live hop indicator",
    "dttl": "Destination IP Time-To-Live hop indicator",
    "stcpb": "Source TCP base sequence number",
    "dtcpb": "Destination TCP base sequence number",
    "sloss": "Source packet retransmission / drop count",
    "dloss": "Destination packet retransmission / drop count",
    "trans_depth": "HTTP pipelined transaction depth",
    "response_body_len": "HTTP response content length in bytes",
    "ct_srv_src": "Connections with same service and source IP",
    "ct_state_ttl": "State-to-TTL combination anomaly ratio",
    "ct_dst_ltm": "Connections to destination IP in window",
    "ct_src_dport_ltm": "Connections from source to destination port",
    "ct_dst_sport_ltm": "Connections to destination from source port",
    "ct_dst_src_ltm": "Connections between same source and destination",
    "is_ftp_login": "FTP authenticated session indicator",
    "ct_ftp_cmd": "FTP commands executed count",
    "ct_flw_http_mthd": "HTTP methods (GET/POST) count in flow",
    "ct_src_ltm": "Connections from source IP in window",
    "ct_srv_dst": "Connections to same service and destination",
    "is_sm_ips_ports": "Land attack indicator (same src/dst IP and port)",
    "proto": "Network transport protocol (TCP, UDP, ICMP)",
    "service": "Application-layer service protocol (HTTP, DNS, SSL)",
    "state": "Connection lifecycle state (CON, REQ, INT, FIN, RST)",
}


class AIExplainabilityEngine:
    """Provides global and local AI explainability for BLACKBOX intrusion predictions."""

    def __init__(self, model_package=None, model_type="live"):
        if model_package is None:
            if model_type == "benchmark":
                model_path = PROJECT_ROOT / "models" / "hybrid_intrusion_model.pkl"
            else:
                model_path = PROJECT_ROOT / "models" / "live_hybrid_intrusion_model.pkl"
                if not model_path.exists():
                    model_path = PROJECT_ROOT / "models" / "hybrid_intrusion_model.pkl"
            self.model_package = joblib.load(model_path)
        else:
            self.model_package = model_package

        self.rf_model = self.model_package["random_forest"]
        self.feature_columns = self.model_package["feature_columns"]
        self.importances = dict(zip(self.feature_columns, self.rf_model.feature_importances_))

    def get_global_importances(self):
        """Returns sorted DataFrame of global feature importances across all forest trees."""
        items = []
        for feat in self.feature_columns:
            imp = self.importances.get(feat, 0.0)
            items.append({
                "Feature": feat,
                "Importance": round(imp * 100, 2),
                "Description": FEATURE_DESCRIPTIONS.get(feat, "Network flow characteristic")
            })
        df = pd.DataFrame(items).sort_values("Importance", ascending=False).reset_index(drop=True)
        return df

    def explain_flow(self, flow_dict_or_series, threshold=0.70):
        """Generates local feature attribution and plain-language explanation for a single flow."""
        values = {}
        for feat in self.feature_columns:
            val = flow_dict_or_series.get(feat, 0.0)
            try:
                values[feat] = float(val)
            except (ValueError, TypeError):
                values[feat] = 0.0

        feat_vector = np.array([[values[c] for c in self.feature_columns]], dtype=np.float32)
        prob = float(self.rf_model.predict_proba(feat_vector)[0, 1])
        is_attack = prob >= threshold

        # Decision path feature traversal across estimators
        feature_hit_counts = {feat: 0 for feat in self.feature_columns}
        for tree in self.rf_model.estimators_:
            indicator = tree.decision_path(feat_vector)
            leaf_id = tree.apply(feat_vector)[0]
            val = tree.tree_.value[leaf_id][0]
            leaf_attack = val[1] > val[0]

            if leaf_attack == is_attack:
                for node_id in indicator.indices:
                    if node_id != leaf_id:
                        f_idx = tree.tree_.feature[node_id]
                        f_name = self.feature_columns[f_idx]
                        feature_hit_counts[f_name] += 1

        top_factors = []
        for feat, hits in sorted(feature_hit_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            imp = self.importances.get(feat, 0.0)
            top_factors.append({
                "Feature": feat,
                "Value": values.get(feat, 0.0),
                "Influence": round((hits / len(self.rf_model.estimators_)) * 100, 1),
                "Description": FEATURE_DESCRIPTIONS.get(feat, "")
            })

        # Plain-English Executive SOC explanation
        if is_attack:
            leading = top_factors[0]["Feature"] if top_factors else "flow profile"
            leading_desc = FEATURE_DESCRIPTIONS.get(leading, leading)
            reason = (
                f"Classified as ATTACK with {prob * 100:.1f}% confidence. "
                f"Primary indicator: abnormal {leading_desc} ({values.get(leading, 0):.2f}) "
                f"combined with matching attack signatures across {top_factors[0]['Influence'] if top_factors else 0}% of forest models."
            )
        else:
            reason = (
                f"Classified as NORMAL ({100 - prob * 100:.1f}% confidence). "
                f"Flow metrics remain consistent with baseline communication boundaries."
            )

        return {
            "Attack_Probability": round(prob * 100, 2),
            "Verdict": "Attack" if is_attack else "Normal",
            "Top_Factors": top_factors,
            "Summary_Reason": reason
        }


def explain_single_flow(flow_record):
    engine = AIExplainabilityEngine()
    return engine.explain_flow(flow_record)
