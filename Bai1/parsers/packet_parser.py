from scapy.layers.inet import IP, TCP, UDP

from detectors.protocol_detector import detect_application_protocol
from parsers.http_parser import parse_http
from parsers.ipv4_parser import parse_ipv4
from parsers.tcp_parser import parse_tcp
from parsers.udp_parser import parse_udp


def process_packet(packet, packet_id: int) -> dict:
    """
    Convert a Scapy packet into a normalized IDS event.

    This pipeline is shared by:
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
        tcp_layer = packet[TCP]

        event["transport"] = parse_tcp(tcp_layer)

        payload = bytes(tcp_layer.payload)

        # Application detection

        application_protocol = detect_application_protocol(
            transport_protocol="TCP",
            src_port=tcp_layer.sport,
            dst_port=tcp_layer.dport,
            payload=payload,
        )

        # Application parsing
        if application_protocol == "HTTP":
            event["application"] = parse_http(payload)

        else:
            event["application"] = {
                "protocol": "UNKNOWN"
            }

    elif UDP in packet:
        udp_layer = packet[UDP]

        event["transport"] = parse_udp(udp_layer)

        # DNS will be added later.
        event["application"] = {
            "protocol": "UNKNOWN"
        }

    return event