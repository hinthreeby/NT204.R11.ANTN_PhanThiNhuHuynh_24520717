from scapy.layers.inet import IP, TCP, UDP

from detectors.protocol_detector import detect_application_protocol
from parsers.dns_parser import parse_dns
from parsers.http_parser import parse_http
from parsers.ipv4_parser import parse_ipv4
from parsers.smtp_parser import parse_smtp
from parsers.tcp_parser import parse_tcp
from parsers.udp_parser import parse_udp


def add_error(
    event: dict,
    stage: str,
    message: str,
) -> None:
    """
    Add an error entry to a normalized IDS event.
    """

    event["errors"].append(
        {
            "stage": stage,
            "message": message,
        }
    )


def create_base_event(
    packet,
    packet_id: int,
) -> dict:
    """
    Create the base normalized IDS event.
    """

    event = {
        "packet_id": packet_id,
        "timestamp": None,

        "network": {
            "protocol": "UNKNOWN"
        },

        "transport": {
            "protocol": "UNKNOWN"
        },

        "application": {
            "protocol": "UNKNOWN"
        },

        "errors": [],
    }

    try:
        if hasattr(packet, "time"):
            event["timestamp"] = float(packet.time)

    except Exception as exc:
        add_error(
            event,
            "timestamp",
            f"{type(exc).__name__}: {exc}",
        )

    return event


def process_packet(
    packet,
    packet_id: int,
) -> dict:
    """
    Convert a Scapy packet into a normalized IDS event.

    The function is designed to avoid crashing when a packet
    is malformed, incomplete, or uses an unsupported protocol.

    This pipeline is shared by:
    - PCAP import
    - Live packet capture
    """

    event = create_base_event(
        packet,
        packet_id,
    )

    # Network layer
    try:
        if IP not in packet:
            add_error(
                event,
                "network",
                "Unsupported or missing IPv4 header",
            )

            return event

        event["network"] = parse_ipv4(
            packet[IP]
        )

    except Exception as exc:
        add_error(
            event,
            "network",
            f"{type(exc).__name__}: {exc}",
        )

        return event

    # TCP
    if TCP in packet:
        tcp_layer = packet[TCP]

        try:
            event["transport"] = parse_tcp(
                tcp_layer
            )

        except Exception as exc:
            add_error(
                event,
                "transport",
                f"{type(exc).__name__}: {exc}",
            )

            return event

        try:
            payload = bytes(
                tcp_layer.payload
            )

        except Exception as exc:
            add_error(
                event,
                "payload",
                f"{type(exc).__name__}: {exc}",
            )

            return event

        # Empty TCP payload is valid.
        # For example, SYN and ACK packets may not carry data.
        if not payload:
            return event

        try:
            application_protocol = (
                detect_application_protocol(
                    transport_protocol="TCP",
                    src_port=tcp_layer.sport,
                    dst_port=tcp_layer.dport,
                    payload=payload,
                )
            )

        except Exception as exc:
            add_error(
                event,
                "application_detection",
                f"{type(exc).__name__}: {exc}",
            )

            return event

        try:
            if application_protocol == "HTTP":
                event["application"] = parse_http(
                    payload
                )

            elif application_protocol == "SMTP":
                event["application"] = parse_smtp(
                    payload
                )

        except Exception as exc:
            event["application"] = {
                "protocol": application_protocol,
                "type": "UNKNOWN",
            }

            add_error(
                event,
                "application_parser",
                f"{type(exc).__name__}: {exc}",
            )

        return event

    # UDP
    if UDP in packet:
        udp_layer = packet[UDP]

        try:
            event["transport"] = parse_udp(
                udp_layer
            )

        except Exception as exc:
            add_error(
                event,
                "transport",
                f"{type(exc).__name__}: {exc}",
            )

            return event

        try:
            payload = bytes(
                udp_layer.payload
            )

        except Exception as exc:
            add_error(
                event,
                "payload",
                f"{type(exc).__name__}: {exc}",
            )

            return event

        # Empty UDP payload should not crash the parser.
        if not payload:
            return event

        try:
            application_protocol = (
                detect_application_protocol(
                    transport_protocol="UDP",
                    src_port=udp_layer.sport,
                    dst_port=udp_layer.dport,
                    payload=payload,
                )
            )

        except Exception as exc:
            add_error(
                event,
                "application_detection",
                f"{type(exc).__name__}: {exc}",
            )

            return event

        try:
            if application_protocol == "DNS":
                event["application"] = parse_dns(
                    payload
                )

        except Exception as exc:
            event["application"] = {
                "protocol": application_protocol,
                "type": "UNKNOWN",
            }

            add_error(
                event,
                "application_parser",
                f"{type(exc).__name__}: {exc}",
            )

        return event

    # Unsupported transport
    add_error(
        event,
        "transport",
        "Unsupported or missing TCP/UDP layer",
    )

    return event