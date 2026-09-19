from scapy.layers.inet import IP, TCP, UDP

from parsers.ipv4_parser import parse_ipv4
from parsers.tcp_parser import parse_tcp
from parsers.udp_parser import parse_udp


def process_packet(packet, packet_id: int) -> dict:
    """
    Convert a Scapy packet into a normalized IDS event.

    This function will be shared by both:
    - PCAP import
    - Live packet capture
    """

    timestamp = None

    if hasattr(packet, "time"):
        try:
            timestamp = float(packet.time)
        except (TypeError, ValueError):
            timestamp = None

    event = {
        "packet_id": packet_id,
        "timestamp": timestamp,
        "network": {
            "protocol": "UNKNOWN"
        },
        "transport": {
            "protocol": "UNKNOWN"
        },
        "application": {
            "protocol": "UNKNOWN"
        },
    }

    # Network layer
    if IP not in packet:
        return event

    event["network"] = parse_ipv4(packet[IP])

    # Transport layer
    if TCP in packet:
        event["transport"] = parse_tcp(packet[TCP])

    elif UDP in packet:
        event["transport"] = parse_udp(packet[UDP])

    return event