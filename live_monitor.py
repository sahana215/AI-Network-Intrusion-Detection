
from scapy.all import sniff, IP, TCP, UDP
import pandas as pd
from datetime import datetime

packets_data = []

def capture_packet(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        packet_size = len(packet)
        ttl = packet[IP].ttl

        if TCP in packet:
            protocol_name = "tcp"
        elif UDP in packet:
            protocol_name = "udp"
        else:
            protocol_name = "other"

        packets_data.append({
            "Time": datetime.now(),
            "Source IP": source_ip,
            "Destination IP": destination_ip,
            "Protocol": protocol_name,
            "Packet Size": packet_size,
            "TTL": ttl
        })

        print(source_ip, "->", destination_ip, protocol_name, packet_size, "TTL:", ttl)

print("Live Network Monitoring Started...")
sniff(prn=capture_packet, count=100, store=False)

df = pd.DataFrame(packets_data)
df.to_csv("live_network_traffic.csv", index=False)

print("\nPacket capture completed!")
print("Saved as live_network_traffic.csv")
