import time
from datetime import datetime
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, conf, get_if_list


def get_available_interfaces():
    """Returns a sorted list of network interfaces, prioritizing active physical and default-route adapters."""
    interfaces = []
    default_gw = ""
    default_ip = ""
    try:
        gw, iface, ip = conf.route.route("0.0.0.0")
        default_gw = str(gw)
        default_ip = str(iface)
    except Exception:
        pass

    try:
        for iface_name, iface in conf.ifaces.items():
            desc = getattr(iface, "description", "") or getattr(iface, "name", "")
            ip = getattr(iface, "ip", "")
            is_default = (ip and ip == default_ip) or (iface.name == default_gw) or (getattr(iface, "network_name", "") == default_gw)
            is_miniport = "wan miniport" in desc.lower()

            if is_default:
                priority = 0
            elif ip and not is_miniport and not ip.startswith("169.254"):
                priority = 1
            elif ip and not is_miniport:
                priority = 2
            elif not is_miniport:
                priority = 3
            else:
                priority = 4

            label = f"{iface.name} ({desc})" if desc and desc != iface.name else iface.name
            if ip:
                label += f" [{ip}]"
            if is_default:
                label += " ★ ACTIVE DEFAULT ROUTE"

            interfaces.append({
                "id": iface.name,
                "label": label,
                "description": desc,
                "ip": ip,
                "is_default": is_default,
                "priority": priority
            })
    except Exception:
        pass

    if not interfaces:
        # Fallback list for common Windows interfaces
        for name in ["WiFi", "Ethernet", "Loopback Pseudo-Interface 1"]:
            interfaces.append({
                "id": name,
                "label": name,
                "description": name,
                "ip": "",
                "is_default": False,
                "priority": 1
            })

    interfaces.sort(key=lambda x: (x["priority"], x["id"]))
    return interfaces


def decode_tcp_flags(flags_int):
    """Decodes integer TCP flags into a human-readable string (e.g. SYN, ACK, FIN-ACK)."""
    flags_map = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR")
    ]
    active = [name for mask, name in flags_map if flags_int & mask]
    return "-".join(active) if active else "NONE"


def extract_packet_info(packet):
    """Extracts deep inspection metadata from a captured packet for SOC analysis.

    Supports IPv4, IPv6, TCP, UDP, ICMP, DNS, TCP flags, TTL, sequence numbers, and payload hex.
    """
    timestamp = float(getattr(packet, "time", time.time()))
    time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]

    source_ip = "Unknown"
    destination_ip = "Unknown"
    protocol = "Other"
    source_port = 0
    destination_port = 0
    ttl = 0
    tos = 0

    if IP in packet:
        ip = packet[IP]
        source_ip = ip.src
        destination_ip = ip.dst
        ttl = ip.ttl
        tos = ip.tos
    elif IPv6 in packet:
        ip = packet[IPv6]
        source_ip = ip.src
        destination_ip = ip.dst
        ttl = ip.hlim

    tcp_flags_str = "-"
    seq_num = 0
    ack_num = 0
    win_size = 0
    dns_query = ""
    icmp_type = "-"
    payload_len = 0
    payload_preview = ""

    if TCP in packet:
        tcp = packet[TCP]
        protocol = "TCP"
        source_port = int(tcp.sport)
        destination_port = int(tcp.dport)
        tcp_flags_str = decode_tcp_flags(int(tcp.flags))
        seq_num = int(tcp.seq)
        ack_num = int(tcp.ack)
        win_size = int(tcp.window)
        raw_payload = bytes(tcp.payload)
        payload_len = len(raw_payload)
        if raw_payload:
            payload_preview = raw_payload[:24].hex(" ").upper()

    elif UDP in packet:
        udp = packet[UDP]
        protocol = "UDP"
        source_port = int(udp.sport)
        destination_port = int(udp.dport)
        raw_payload = bytes(udp.payload)
        payload_len = len(raw_payload)
        if raw_payload:
            payload_preview = raw_payload[:24].hex(" ").upper()

        if DNS in packet and packet[DNS].qd is not None:
            try:
                dns_query = packet[DNS].qd.qname.decode(errors="ignore").rstrip(".")
            except Exception:
                dns_query = "DNS Query"

    elif ICMP in packet:
        icmp = packet[ICMP]
        protocol = "ICMP"
        icmp_type = f"Type {icmp.type} (Code {icmp.code})"
        raw_payload = bytes(icmp.payload)
        payload_len = len(raw_payload)
        if raw_payload:
            payload_preview = raw_payload[:24].hex(" ").upper()

    return {
        "Timestamp": time_str,
        "Source IP": source_ip,
        "Destination IP": destination_ip,
        "Protocol": protocol,
        "Source Port": source_port,
        "Destination Port": destination_port,
        "Packet Size": len(packet),
        "TTL": ttl,
        "TOS": tos,
        "TCP Flags": tcp_flags_str,
        "Seq Number": seq_num,
        "Ack Number": ack_num,
        "Window Size": win_size,
        "Info": dns_query or icmp_type or f"{protocol} {source_port} -> {destination_port}",
        "Payload Bytes": payload_len,
        "Payload Hex": payload_preview or "None",
    }


def capture_live_packets(interface="WiFi", packet_limit=0, callback=None):
    """Continuously capture live network packets."""
    print(f"BLACKBOX Live Monitoring Started on [{interface}]...")
    print("Press CTRL+C to stop monitoring.\n")

    packet_count = 0

    def process_packet(packet):
        nonlocal packet_count
        packet_count += 1
        record = extract_packet_info(packet)
        if callback:
            callback(record, packet)
        else:
            print(f"Packet {packet_count}: {record}")

    sniff(
        iface=interface,
        prn=process_packet,
        store=False,
        count=packet_limit
    )


if __name__ == "__main__":
    print("Available Interfaces:")
    for iface in get_available_interfaces():
        print(" -", iface["label"])
