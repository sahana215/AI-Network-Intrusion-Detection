
import time
from collections import deque
from statistics import mean, pstdev
from scapy.all import IP, IPv6, TCP, UDP, ICMP


class FlowAggregator:
    """Production-grade bi-directional network flow aggregation engine with
    automatic idle-flow timeout, memory bounding, and intelligent directional orientation.
    """

    TCP_SERVICE_PORTS = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 25: "smtp",
        53: "dns", 80: "http", 110: "pop3", 143: "imap",
        443: "ssl", 465: "smtp", 587: "smtp", 993: "imap",
        995: "pop3", 8080: "http", 8443: "ssl", 6667: "irc",
    }

    UDP_SERVICE_PORTS = {
        53: "dns", 67: "dhcp", 68: "dhcp", 123: "ntp",
        161: "snmp", 162: "snmp", 443: "ssl",
        1812: "radius", 1813: "radius",
    }

    WELL_KNOWN_SERVER_PORTS = {
        20, 21, 22, 23, 25, 53, 67, 68, 80, 110, 123, 143,
        161, 162, 443, 465, 587, 993, 995, 1812, 1813,
        3306, 3389, 5432, 8080, 8443
    }

    DEFAULT_TCP_TIMEOUT = 120.0
    DEFAULT_UDP_TIMEOUT = 30.0
    DEFAULT_CLOSED_TIMEOUT = 5.0
    DEFAULT_DNS_TIMEOUT = 10.0
    MAX_HISTORICAL_FLOWS = 2000

    def __init__(self, tcp_timeout=DEFAULT_TCP_TIMEOUT, udp_timeout=DEFAULT_UDP_TIMEOUT):
        self.flows = {}
        self.completed_flows = deque(maxlen=self.MAX_HISTORICAL_FLOWS)
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.total_flows_created = 0
        self.total_packets_processed = 0

    def _determine_direction(self, src_ip, dst_ip, src_port, dst_port, proto, flags=0):
        if proto == "tcp" and (flags & 0x02) and not (flags & 0x10):
            return src_ip, src_port, dst_ip, dst_port, True

        src_is_server = src_port in self.WELL_KNOWN_SERVER_PORTS
        dst_is_server = dst_port in self.WELL_KNOWN_SERVER_PORTS

        if src_is_server and not dst_is_server:
            return dst_ip, dst_port, src_ip, src_port, False

        return src_ip, src_port, dst_ip, dst_port, True

    def add_packet(self, packet):
        self.total_packets_processed += 1

        if IP in packet:
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            ttl = ip.ttl
            network_proto = ip.proto
        elif IPv6 in packet:
            ip = packet[IPv6]
            src_ip = ip.src
            dst_ip = ip.dst
            ttl = ip.hlim
            network_proto = ip.nh
        else:
            return None

        if TCP in packet:
            transport = packet[TCP]
            proto = "tcp"
            src_port = int(transport.sport)
            dst_port = int(transport.dport)
            window = int(transport.window)
            seq = int(transport.seq)
            flags = int(transport.flags)
        elif UDP in packet:
            transport = packet[UDP]
            proto = "udp"
            src_port = int(transport.sport)
            dst_port = int(transport.dport)
            window = seq = flags = 0
        else:
            src_port = dst_port = 0
            window = seq = flags = 0
            if ICMP in packet or network_proto in (1, 58):
                proto = "icmp"
            else:
                proto = "unas"

        source = (src_ip, src_port)
        destination = (dst_ip, dst_port)
        flow_key = (proto, tuple(sorted([source, destination])))

        timestamp = float(getattr(packet, "time", time.time()))
        size = len(ip)

        if self.total_packets_processed % 100 == 0:
            self.evict_expired_flows(timestamp)

        if flow_key not in self.flows:
            self.total_flows_created += 1

            init_ip, init_port, resp_ip, resp_port, is_forward = (
                self._determine_direction(
                    src_ip, dst_ip, src_port, dst_port, proto, flags
                )
            )

            self.flows[flow_key] = {
                "Source IP": init_ip,
                "Destination IP": resp_ip,
                "Source Port": init_port,
                "Destination Port": resp_port,
                "Protocol": proto.upper(),

                "Start Time": timestamp,
                "Last Time": timestamp,

                "Total Packets": 0,
                "Forward Packets": 0,
                "Backward Packets": 0,

                "Forward Bytes": 0,
                "Backward Bytes": 0,

                "Forward Sizes": [],
                "Backward Sizes": [],

                "Forward TTLs": [],
                "Backward TTLs": [],

                "Forward IAT": [],
                "Backward IAT": [],

                "Last Forward Time": None,
                "Last Backward Time": None,

                "Forward TCP Windows": [],
                "Backward TCP Windows": [],

                "Forward TCP Base Sequence": None,
                "Backward TCP Base Sequence": None,

                "Forward SYN Time": None,
                "Backward SYNACK Time": None,
                "First ACK Time": None,

                "State": "INT",
                "Last Flags": flags,
            }

        flow = self.flows[flow_key]

        forward = (
            src_ip == flow["Source IP"]
            and dst_ip == flow["Destination IP"]
            and src_port == flow["Source Port"]
            and dst_port == flow["Destination Port"]
        )

        flow["Last Time"] = timestamp
        flow["Total Packets"] += 1
        flow["Last Flags"] = flags

        if forward:
            flow["Forward Packets"] += 1
            flow["Forward Bytes"] += size
            flow["Forward Sizes"].append(size)
            flow["Forward TTLs"].append(ttl)

            previous = flow["Last Forward Time"]
            if previous is not None:
                flow["Forward IAT"].append(
                    max(timestamp - previous, 0.0) * 1000.0
                )
            flow["Last Forward Time"] = timestamp

            if proto == "tcp":
                flow["Forward TCP Windows"].append(window)
                if flow["Forward TCP Base Sequence"] is None:
                    flow["Forward TCP Base Sequence"] = seq
        else:
            flow["Backward Packets"] += 1
            flow["Backward Bytes"] += size
            flow["Backward Sizes"].append(size)
            flow["Backward TTLs"].append(ttl)

            previous = flow["Last Backward Time"]
            if previous is not None:
                flow["Backward IAT"].append(
                    max(timestamp - previous, 0.0) * 1000.0
                )
            flow["Last Backward Time"] = timestamp

            if proto == "tcp":
                flow["Backward TCP Windows"].append(window)
                if flow["Backward TCP Base Sequence"] is None:
                    flow["Backward TCP Base Sequence"] = seq

        if proto == "tcp":
            syn = bool(flags & 0x02)
            ack_flag = bool(flags & 0x10)
            fin = bool(flags & 0x01)
            rst = bool(flags & 0x04)

            if rst:
                flow["State"] = "RST"
            elif fin:
                flow["State"] = "FIN"
            elif syn and not ack_flag:
                flow["State"] = "REQ"
                if flow["Forward SYN Time"] is None:
                    flow["Forward SYN Time"] = timestamp
            elif syn and ack_flag and not forward:
                if flow["Backward SYNACK Time"] is None:
                    flow["Backward SYNACK Time"] = timestamp
            elif (
                ack_flag
                and forward
                and flow["Backward SYNACK Time"] is not None
                and flow["First ACK Time"] is None
            ):
                flow["First ACK Time"] = timestamp
                flow["State"] = "CON"
            elif ack_flag and flow["State"] not in ("FIN", "RST"):
                flow["State"] = "CON"

        elif proto == "udp":
            if flow["Forward Packets"] > 0 and flow["Backward Packets"] > 0:
                flow["State"] = "CON"
            else:
                flow["State"] = "INT"

        return flow_key

    def evict_expired_flows(self, current_time=None):
        if current_time is None:
            current_time = time.time()

        expired_keys = []

        for key, flow in self.flows.items():
            proto = key[0]
            state = flow["State"]
            idle_time = current_time - flow["Last Time"]

            if proto == "tcp":
                if state in ("FIN", "RST") and idle_time >= self.DEFAULT_CLOSED_TIMEOUT:
                    expired_keys.append(key)
                elif state == "REQ" and idle_time >= 15.0:
                    expired_keys.append(key)
                elif idle_time >= self.tcp_timeout:
                    expired_keys.append(key)

            elif proto == "udp":
                service = (
                    self.UDP_SERVICE_PORTS.get(flow["Destination Port"])
                    or self.UDP_SERVICE_PORTS.get(flow["Source Port"])
                )
                timeout = (
                    self.DEFAULT_DNS_TIMEOUT
                    if service == "dns"
                    else self.udp_timeout
                )
                if idle_time >= timeout:
                    expired_keys.append(key)

            elif idle_time >= 30.0:
                expired_keys.append(key)

        for key in expired_keys:
            expired_flow = self.flows.pop(key, None)
            if expired_flow:
                self.completed_flows.append(expired_flow)

        return len(expired_keys)

    def _format_flow_summary(self, flow):
        duration = max(flow["Last Time"] - flow["Start Time"], 0.0)

        spkts = flow["Forward Packets"]
        dpkts = flow["Backward Packets"]
        sbytes = flow["Forward Bytes"]
        dbytes = flow["Backward Bytes"]
        total_packets = flow["Total Packets"]
        total_bytes = sbytes + dbytes

        forward_sizes = flow["Forward Sizes"]
        backward_sizes = flow["Backward Sizes"]
        forward_iat = flow["Forward IAT"]
        backward_iat = flow["Backward IAT"]
        forward_ttl = flow["Forward TTLs"]
        backward_ttl = flow["Backward TTLs"]
        forward_windows = flow["Forward TCP Windows"]
        backward_windows = flow["Backward TCP Windows"]

        synack = 0.0
        ackdat = 0.0

        if (
            flow["Forward SYN Time"] is not None
            and flow["Backward SYNACK Time"] is not None
        ):
            synack = max(
                flow["Backward SYNACK Time"] - flow["Forward SYN Time"], 0.0
            )

        if (
            flow["Backward SYNACK Time"] is not None
            and flow["First ACK Time"] is not None
        ):
            ackdat = max(
                flow["First ACK Time"] - flow["Backward SYNACK Time"], 0.0
            )

        service = "-"
        proto_lower = flow["Protocol"].lower()

        if proto_lower == "tcp":
            service = (
                self.TCP_SERVICE_PORTS.get(flow["Destination Port"])
                or self.TCP_SERVICE_PORTS.get(flow["Source Port"])
                or "-"
            )
        elif proto_lower == "udp":
            service = (
                self.UDP_SERVICE_PORTS.get(flow["Destination Port"])
                or self.UDP_SERVICE_PORTS.get(flow["Source Port"])
                or "-"
            )

        rate = (total_packets / duration) if duration > 0.0 else 0.0
        sload = (sbytes * 8.0 / duration) if duration > 0.0 else 0.0
        dload = (dbytes * 8.0 / duration) if duration > 0.0 else 0.0

        sinpkt = mean(forward_iat) if forward_iat else 0.0
        dinpkt = mean(backward_iat) if backward_iat else 0.0

        sjit = pstdev(forward_iat) if len(forward_iat) > 1 else 0.0
        djit = pstdev(backward_iat) if len(backward_iat) > 1 else 0.0

        swin = mean(forward_windows) if forward_windows else 0.0
        dwin = mean(backward_windows) if backward_windows else 0.0

        return {
            "Source IP": flow["Source IP"],
            "Destination IP": flow["Destination IP"],
            "Source Port": flow["Source Port"],
            "Destination Port": flow["Destination Port"],
            "Protocol": flow["Protocol"],

            # Added for live monitoring reports
            "Start Time": flow["Start Time"],
            "Last Time": flow["Last Time"],

            "Flow ID": (
                f"{flow['Source IP']}:{flow['Source Port']}-"
                f"{flow['Destination IP']}:{flow['Destination Port']}"
            ),

            "dur": round(duration, 6),
            "proto": proto_lower,
            "service": service,
            "state": flow["State"],

            "spkts": spkts,
            "dpkts": dpkts,
            "sbytes": sbytes,
            "dbytes": dbytes,

            "rate": round(rate, 6),
            "sttl": round(mean(forward_ttl), 2) if forward_ttl else 0.0,
            "dttl": round(mean(backward_ttl), 2) if backward_ttl else 0.0,

            "sload": round(sload, 6),
            "dload": round(dload, 6),

            "sinpkt": round(sinpkt, 6),
            "dinpkt": round(dinpkt, 6),

            "sjit": round(sjit, 6),
            "djit": round(djit, 6),

            "swin": round(swin, 2),
            "dwin": round(dwin, 2),

            "stcpb": flow["Forward TCP Base Sequence"] or 0,
            "dtcpb": flow["Backward TCP Base Sequence"] or 0,

            "tcprtt": round(synack + ackdat, 6),
            "synack": round(synack, 6),
            "ackdat": round(ackdat, 6),

            "smean": round(mean(forward_sizes), 2) if forward_sizes else 0.0,
            "dmean": round(mean(backward_sizes), 2) if backward_sizes else 0.0,

            "Duration": round(duration, 6),
            "Total Packets": total_packets,
            "Total Bytes": total_bytes,
        }

    def get_flow_summary(self, include_recent_completed=True):
        self.evict_expired_flows()

        summaries = []

        for flow in self.flows.values():
            summaries.append(self._format_flow_summary(flow))

        if include_recent_completed and self.completed_flows:
            recent_completed = list(self.completed_flows)[-50:]
            for flow in recent_completed:
                summaries.append(self._format_flow_summary(flow))

        return summaries

    def clear_flows(self):
        self.flows.clear()
        self.completed_flows.clear()

    def get_stats(self):
        return {
            "active_flows": len(self.flows),
            "completed_flows": len(self.completed_flows),
            "total_flows_created": self.total_flows_created,
            "total_packets_processed": self.total_packets_processed,
        }
