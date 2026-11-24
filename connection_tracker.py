import time
from collections import defaultdict, deque
from datetime import datetime


class ConnectionTracker:
    """Tracks active and historical network connections, monitoring state lifecycles,

    session timeouts, and repeated connection patterns.
    """

    def __init__(self, max_history=1000):
        self.active_sessions = {}
        self.closed_sessions = deque(maxlen=max_history)
        self.host_pair_counts = defaultdict(int)

    def update_connection(self, flow_summary):
        """Updates connection state tracking from flow summary record."""
        flow_id = flow_summary.get("Flow ID", "")
        proto = flow_summary.get("Protocol", "TCP").upper()
        state = flow_summary.get("state", "INT")
        now = time.time()

        src_ip = flow_summary.get("Source IP", "")
        dst_ip = flow_summary.get("Destination IP", "")
        host_pair = (src_ip, dst_ip)

        if flow_id not in self.active_sessions:
            self.host_pair_counts[host_pair] += 1
            self.active_sessions[flow_id] = {
                "Flow ID": flow_id,
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Source Port": flow_summary.get("Source Port", 0),
                "Destination Port": flow_summary.get("Destination Port", 0),
                "Protocol": proto,
                "Service": flow_summary.get("service", "-"),
                "State": state,
                "Start Time": datetime.now().strftime("%H:%M:%S"),
                "Last Active": now,
                "Packets": flow_summary.get("Total Packets", 1),
                "Bytes": flow_summary.get("Total Bytes", 0),
                "Duration": flow_summary.get("dur", 0.0),
                "Repeated Count": self.host_pair_counts[host_pair],
                "Status": "ACTIVE"
            }
        else:
            session = self.active_sessions[flow_id]
            session["State"] = state
            session["Last Active"] = now
            session["Packets"] = flow_summary.get("Total Packets", session["Packets"])
            session["Bytes"] = flow_summary.get("Total Bytes", session["Bytes"])
            session["Duration"] = flow_summary.get("dur", session["Duration"])

            if state in ("FIN", "RST"):
                session["Status"] = "CLOSING"

    def audit_timeouts(self, tcp_idle_timeout=120.0, udp_idle_timeout=30.0):
        """Identifies and transitions inactive connections to CLOSED / TIMED_OUT."""
        now = time.time()
        expired_ids = []

        for flow_id, session in self.active_sessions.items():
            idle = now - session["Last Active"]
            proto = session["Protocol"]
            state = session["State"]

            if proto == "TCP":
                if state in ("FIN", "RST") and idle >= 5.0:
                    session["Status"] = "TERMINATED"
                    expired_ids.append(flow_id)
                elif idle >= tcp_idle_timeout:
                    session["Status"] = "TIMED_OUT"
                    expired_ids.append(flow_id)
            elif proto == "UDP" and idle >= udp_idle_timeout:
                session["Status"] = "TIMED_OUT"
                expired_ids.append(flow_id)

        for fid in expired_ids:
            closed_session = self.active_sessions.pop(fid)
            self.closed_sessions.append(closed_session)

        return len(expired_ids)

    def get_all_sessions(self, limit=100):
        self.audit_timeouts()
        active = list(self.active_sessions.values())
        closed = list(self.closed_sessions)
        return (active + closed)[-limit:]

    def get_repeated_connections(self, threshold=5):
        """Returns host pairs exhibiting frequent repeated connection behavior."""
        repeated = []
        for (src, dst), count in self.host_pair_counts.items():
            if count >= threshold:
                repeated.append({
                    "Source IP": src,
                    "Destination IP": dst,
                    "Total Sessions": count,
                    "Risk Level": "HIGH" if count >= 20 else "MEDIUM"
                })
        return sorted(repeated, key=lambda x: x["Total Sessions"], reverse=True)
