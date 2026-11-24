import pandas as pd


class AttackBehaviourEngine:
    """Heuristic-based network attack behaviour analysis and host profiling."""

    AUTH_PORTS = {
        21, 22, 23, 25, 110, 143,
        445, 1433, 1521, 3306, 3389, 5432, 5900
    }

    def __init__(
        self,
        port_scan_threshold=10,
        syn_flood_threshold=10,
        brute_force_threshold=5,
        dos_packet_threshold=500,
        high_volume_threshold=1_000_000,
        repeated_connection_threshold=20
    ):
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.brute_force_threshold = brute_force_threshold
        self.dos_packet_threshold = dos_packet_threshold
        self.high_volume_threshold = high_volume_threshold
        self.repeated_connection_threshold = repeated_connection_threshold

    def analyse(self, flow_data):
        if flow_data is None or len(flow_data) == 0:
            return pd.DataFrame()

        df = pd.DataFrame(flow_data).copy()

        required_columns = [
            "Source IP", "Destination IP", "Destination Port",
            "Total Packets", "Total Bytes", "Duration",
            "Forward Packets", "Backward Packets", "state"
        ]

        if "Forward Packets" not in df.columns:
            df["Forward Packets"] = df["spkts"] if "spkts" in df.columns else 0

        if "Backward Packets" not in df.columns:
            df["Backward Packets"] = df["dpkts"] if "dpkts" in df.columns else 0

        for column in required_columns:
            if column not in df.columns:
                df[column] = 0

        numeric_columns = [
            "Destination Port", "Total Packets", "Total Bytes",
            "Duration", "Forward Packets", "Backward Packets"
        ]

        for column in numeric_columns:
            df[column] = pd.to_numeric(df[column], errors="coerce").fillna(0)

        df["Source IP"] = df["Source IP"].fillna("Unknown").astype(str)
        df["Destination IP"] = df["Destination IP"].fillna("Unknown").astype(str)
        df["state"] = df["state"].fillna("").astype(str).str.upper()

        results = []

        def add_detection(source_ip, behaviour, severity, confidence, reason, affected_flows):
            results.append({
                "Source IP": source_ip,
                "Attack Behaviour": behaviour,
                "Severity": severity,
                "Confidence": confidence,
                "Affected Flows": int(affected_flows),
                "Detection Reason": reason
            })

        for source_ip, group in df.groupby("Source IP"):
            if source_ip in ("Unknown", "0.0.0.0", "-"):
                continue

            flow_count = len(group)
            total_packets = group["Total Packets"].sum()
            total_bytes = group["Total Bytes"].sum()

            # 1. Vertical Port Scanning
            unique_ports = group.loc[group["Destination Port"] > 0, "Destination Port"].nunique()
            if unique_ports >= self.port_scan_threshold:
                add_detection(
                    source_ip, "Vertical Port Scan", "HIGH",
                    min(95, 60 + unique_ports),
                    f"Host contacted {unique_ports} distinct destination ports across targets.",
                    flow_count
                )

            # 2. Horizontal Subnet Sweep (Same port across multiple IPs)
            port_ip_counts = group.loc[group["Destination Port"] > 0].groupby("Destination Port")["Destination IP"].nunique()
            swept_ports = port_ip_counts[port_ip_counts >= 5]
            if not swept_ports.empty:
                for swept_port, target_count in swept_ports.items():
                    add_detection(
                        source_ip, "Horizontal Subnet Sweep", "HIGH", 85,
                        f"Host scanned port {int(swept_port)} across {target_count} distinct destinations.",
                        target_count
                    )

            # 3. SYN Flood Behaviour
            syn_flows = group[group["state"] == "REQ"]
            syn_count = len(syn_flows)
            if syn_count >= self.syn_flood_threshold:
                syn_ratio = syn_count / flow_count
                if syn_ratio >= 0.5:
                    add_detection(
                        source_ip, "SYN Flood Behaviour", "CRITICAL",
                        min(98, 65 + syn_count),
                        f"{syn_count} half-open connection flows observed with REQ (unacknowledged SYN) state.",
                        syn_count
                    )

            # 4. DoS-like High Volume Packet Burst
            packet_rates = group["Total Packets"] / group["Duration"].clip(lower=0.001)
            peak_packet_rate = packet_rates.max()
            if total_packets >= self.dos_packet_threshold or peak_packet_rate >= 150:
                add_detection(
                    source_ip, "DoS Flooding Pattern", "HIGH", 88,
                    f"High-velocity transmission ({int(total_packets)} packets, peak rate: {peak_packet_rate:.1f} pkts/sec).",
                    flow_count
                )

            # 5. Repeated Authentication-Port Connections (Brute Force)
            auth_flows = group[group["Destination Port"].isin(self.AUTH_PORTS)]
            auth_count = len(auth_flows)
            if auth_count >= self.brute_force_threshold:
                auth_ports = sorted(auth_flows["Destination Port"].astype(int).unique().tolist())
                add_detection(
                    source_ip, "Credential Brute Force Probe", "HIGH", 80,
                    f"{auth_count} repeated attempts targeting authentication ports: {auth_ports}.",
                    auth_count
                )

            # 6. Large Data Transfer / Potential Exfiltration
            if total_bytes >= self.high_volume_threshold:
                add_detection(
                    source_ip, "Abnormal Data Volume Transfer", "MEDIUM", 70,
                    f"Transferred {int(total_bytes):,} bytes across {flow_count} active sessions.",
                    flow_count
                )

            # 7. Asymmetric One-Way Session Pattern
            forward = group["Forward Packets"].sum()
            backward = group["Backward Packets"].sum()
            one_way_ratio = max(forward, backward) / max(forward + backward, 1)
            if flow_count >= self.repeated_connection_threshold and one_way_ratio >= 0.90:
                add_detection(
                    source_ip, "Suspicious One-Way Connection Ratio", "MEDIUM", 70,
                    f"{flow_count} sessions with {one_way_ratio * 100:.1f}% traffic in one direction (potential probing/beaconing).",
                    flow_count
                )

        columns = [
            "Source IP", "Attack Behaviour", "Severity",
            "Confidence", "Affected Flows", "Detection Reason"
        ]
        result_df = pd.DataFrame(results, columns=columns)

        if not result_df.empty:
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            result_df["_order"] = result_df["Severity"].map(severity_order)
            result_df = result_df.sort_values("_order").drop(columns="_order").reset_index(drop=True)

        return result_df

    def profile_hosts(self, flow_data):
        """Generates comprehensive entity profiling summaries for every observed host."""
        if flow_data is None or len(flow_data) == 0:
            return pd.DataFrame()

        df = pd.DataFrame(flow_data).copy()
        if "Source IP" not in df.columns:
            return pd.DataFrame()

        profiles = []
        behaviors_df = self.analyse(df)

        for src_ip, group in df.groupby("Source IP"):
            if src_ip in ("Unknown", "0.0.0.0", "-"):
                continue

            flow_count = len(group)
            total_pkts = int(group.get("Total Packets", pd.Series(1)).sum())
            total_bytes = int(group.get("Total Bytes", pd.Series(0)).sum())
            unique_targets = group.get("Destination IP", pd.Series()).nunique()
            unique_ports = group.get("Destination Port", pd.Series()).nunique()

            host_behaviors = behaviors_df[behaviors_df["Source IP"] == src_ip] if not behaviors_df.empty else pd.DataFrame()
            threat_count = len(host_behaviors)

            if not host_behaviors.empty:
                max_sev = host_behaviors["Severity"].iloc[0]
            else:
                max_sev = "NORMAL"

            profiles.append({
                "Host IP": src_ip,
                "Threat Posture": max_sev,
                "Active Flows": flow_count,
                "Total Packets": total_pkts,
                "Total Bytes": total_bytes,
                "Unique Targets": unique_targets,
                "Ports Contacted": unique_ports,
                "Threat Indicators": threat_count,
                "Top Behavior": host_behaviors["Attack Behaviour"].iloc[0] if not host_behaviors.empty else "Normal Communication"
            })

        prof_df = pd.DataFrame(profiles)
        if not prof_df.empty:
            sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "NORMAL": 3}
            prof_df["_ord"] = prof_df["Threat Posture"].map(sev_order).fillna(4)
            prof_df = prof_df.sort_values("_ord").drop(columns="_ord").reset_index(drop=True)

        return prof_df


def detect_attack_behaviours(flow_data):
    engine = AttackBehaviourEngine()
    return engine.analyse(flow_data)


def profile_network_hosts(flow_data):
    engine = AttackBehaviourEngine()
    return engine.profile_hosts(flow_data)
