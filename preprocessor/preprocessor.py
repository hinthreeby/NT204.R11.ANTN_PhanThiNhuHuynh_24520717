from copy import deepcopy
from ipaddress import ip_address
import math

from config import IDSConfig


NETWORK_PROTOCOL_MAP = {
    "IP": "IPv4",
    "IPV4": "IPv4",
    "IP4": "IPv4",
}

SUPPORTED_TRANSPORT_PROTOCOLS = {
    "TCP",
    "UDP",
}

SUPPORTED_APPLICATION_PROTOCOLS = {
    "HTTP",
    "DNS",
    "SMTP",
    "UNKNOWN",
}


def normalize_ipv4(
    value,
) -> str | None:
    """
    Normalize an IPv4 address into canonical string form.
    """

    if value is None:
        return None

    try:
        parsed = ip_address(
            str(value).strip()
        )

    except ValueError:
        return None

    if parsed.version != 4:
        return None

    return str(parsed)


def normalize_timestamp(
    value,
) -> float | None:
    """
    Normalize timestamp into a finite non-negative float.
    """

    if value is None:
        return None

    if isinstance(value, bool):
        return None

    try:
        timestamp = float(value)

    except (TypeError, ValueError):
        return None

    if (
        not math.isfinite(timestamp)
        or timestamp < 0
    ):
        return None

    return timestamp


def normalize_port(
    value,
) -> int | None:
    """
    Normalize a TCP/UDP port and validate its range.
    """

    if value is None:
        return None

    if isinstance(value, bool):
        return None

    try:
        port = int(value)

    except (TypeError, ValueError):
        return None

    if not 0 <= port <= 65535:
        return None

    return port


def normalize_headers(
    headers: dict,
) -> dict:
    """
    Normalize HTTP/MIME header names.

    Header names are case-insensitive, so lowercase names
    provide one consistent representation.
    """

    normalized = {}

    for name, value in headers.items():
        normalized_name = (
            str(name)
            .strip()
            .lower()
        )

        if isinstance(value, str):
            normalized_value = (
                value.strip()
            )

        else:
            normalized_value = value

        # Host names are case-insensitive.
        if (
            normalized_name == "host"
            and isinstance(
                normalized_value,
                str,
            )
        ):
            normalized_value = (
                normalized_value.lower()
            )

        normalized[
            normalized_name
        ] = normalized_value

    return normalized


def normalize_domain(
    value,
) -> str | None:
    """
    Normalize a domain name.
    """

    if value is None:
        return None

    domain = str(value).strip()

    if not domain:
        return None

    return (
        domain
        .rstrip(".")
        .lower()
    )


class Preprocessor:
    """
    Validate and normalize decoded IDS events.
    """

    def __init__(
        self,
        config: IDSConfig,
    ) -> None:
        self.config = config

    def process(
        self,
        event: dict,
    ) -> dict:
        """
        Validate and normalize one decoded IDS event.
        """

        result = deepcopy(
            event
        )

        partial_reasons = []
        invalid_reasons = []

        # -------------------------
        # Timestamp
        # -------------------------

        timestamp = normalize_timestamp(
            result.get("timestamp")
        )

        if timestamp is None:
            invalid_reasons.append(
                "Missing or invalid timestamp"
            )

            result["timestamp"] = None

        else:
            result["timestamp"] = (
                timestamp
            )

        # -------------------------
        # Network layer
        # -------------------------

        network = result.get(
            "network"
        )

        if not isinstance(
            network,
            dict,
        ):
            network = {
                "protocol": "UNKNOWN",
                "src_ip": None,
                "dst_ip": None,
            }

            result["network"] = (
                network
            )

            invalid_reasons.append(
                "Missing or invalid network data"
            )

        raw_network_protocol = str(
            network.get(
                "protocol",
                "UNKNOWN",
            )
        ).strip().upper()

        normalized_network_protocol = (
            NETWORK_PROTOCOL_MAP.get(
                raw_network_protocol
            )
        )

        if (
            normalized_network_protocol
            is None
        ):
            network["protocol"] = (
                "UNKNOWN"
            )

            invalid_reasons.append(
                "Unsupported network protocol: "
                f"{raw_network_protocol}"
            )

        else:
            network["protocol"] = (
                normalized_network_protocol
            )

        src_ip = normalize_ipv4(
            network.get("src_ip")
        )

        dst_ip = normalize_ipv4(
            network.get("dst_ip")
        )

        if src_ip is None:
            invalid_reasons.append(
                "Missing or invalid source IP"
            )

        if dst_ip is None:
            invalid_reasons.append(
                "Missing or invalid destination IP"
            )

        network["src_ip"] = src_ip
        network["dst_ip"] = dst_ip

        # -------------------------
        # Transport layer
        # -------------------------

        transport = result.get(
            "transport"
        )

        if not isinstance(
            transport,
            dict,
        ):
            transport = {
                "protocol": "UNKNOWN",
                "src_port": None,
                "dst_port": None,
            }

            result["transport"] = (
                transport
            )

            invalid_reasons.append(
                "Missing or invalid transport data"
            )

        raw_transport_protocol = str(
            transport.get(
                "protocol",
                "UNKNOWN",
            )
        ).strip().upper()

        if (
            raw_transport_protocol
            in SUPPORTED_TRANSPORT_PROTOCOLS
        ):
            transport["protocol"] = (
                raw_transport_protocol
            )

            src_port = normalize_port(
                transport.get("src_port")
            )

            dst_port = normalize_port(
                transport.get("dst_port")
            )

            if src_port is None:
                invalid_reasons.append(
                    "Missing or invalid source port"
                )

            if dst_port is None:
                invalid_reasons.append(
                    "Missing or invalid destination port"
                )

            transport["src_port"] = (
                src_port
            )

            transport["dst_port"] = (
                dst_port
            )

        elif (
            raw_transport_protocol
            == "UNKNOWN"
        ):
            transport["protocol"] = (
                "UNKNOWN"
            )

            partial_reasons.append(
                "Unknown transport protocol"
            )

            transport.setdefault(
                "src_port",
                None,
            )

            transport.setdefault(
                "dst_port",
                None,
            )

        else:
            transport["protocol"] = (
                "UNKNOWN"
            )

            partial_reasons.append(
                "Unsupported transport protocol: "
                f"{raw_transport_protocol}"
            )

            transport.setdefault(
                "src_port",
                None,
            )

            transport.setdefault(
                "dst_port",
                None,
            )

        # -------------------------
        # Application layer
        # -------------------------

        application = result.get(
            "application"
        )

        if not isinstance(
            application,
            dict,
        ):
            application = {
                "protocol": "UNKNOWN"
            }

            result["application"] = (
                application
            )

            partial_reasons.append(
                "Missing application data"
            )

        raw_application_protocol = str(
            application.get(
                "protocol",
                "UNKNOWN",
            )
        ).strip().upper()

        if (
            raw_application_protocol
            in SUPPORTED_APPLICATION_PROTOCOLS
        ):
            application["protocol"] = (
                raw_application_protocol
            )

        else:
            application["protocol"] = (
                "UNKNOWN"
            )

            partial_reasons.append(
                "Unsupported application protocol: "
                f"{raw_application_protocol}"
            )

        # -------------------------
        # Header normalization
        # -------------------------

        if "headers" in application:
            headers = application.get(
                "headers"
            )

            if isinstance(
                headers,
                dict,
            ):
                application["headers"] = (
                    normalize_headers(
                        headers
                    )
                )

            else:
                application["headers"] = {}

                partial_reasons.append(
                    "Invalid application headers"
                )

        # -------------------------
        # Domain normalization
        # -------------------------

        if "domain" in application:
            domain = normalize_domain(
                application.get(
                    "domain"
                )
            )

            application["domain"] = (
                domain
            )

            if domain is None:
                partial_reasons.append(
                    "Invalid domain value"
                )

        answers = application.get(
            "answers"
        )

        if isinstance(
            answers,
            list,
        ):
            for answer in answers:
                if (
                    isinstance(answer, dict)
                    and "name" in answer
                ):
                    answer["name"] = (
                        normalize_domain(
                            answer.get("name")
                        )
                    )

        # -------------------------
        # URI normalization
        # -------------------------

        uri = application.get(
            "decoded_uri"
        )

        if uri is None:
            uri = application.get(
                "uri"
            )

        if isinstance(uri, str):
            application[
                "normalized_uri"
            ] = uri.strip()

        # -------------------------
        # Missing error list
        # -------------------------

        if "errors" not in result:
            result["errors"] = []

            partial_reasons.append(
                "Missing errors field"
            )

        elif not isinstance(
            result["errors"],
            list,
        ):
            result["errors"] = []

            partial_reasons.append(
                "Invalid errors field"
            )

        elif result["errors"]:
            partial_reasons.append(
                "Upstream processing reported errors"
            )

        # -------------------------
        # Decoder status
        # -------------------------

        decoder_metadata = (
            result.get("decoder")
        )

        if (
            isinstance(
                decoder_metadata,
                dict,
            )
            and decoder_metadata.get(
                "status"
            ) == "partial"
        ):
            partial_reasons.append(
                "Decoder reported partial result"
            )

        # -------------------------
        # Preprocess metadata
        # -------------------------

        if invalid_reasons:
            status = "invalid"

        elif partial_reasons:
            status = "partial"

        else:
            status = "valid"

        if (
            status == "invalid"
            and
            self.config.skip_invalid_events
        ):
            action = "skip"

        else:
            action = "continue"

        reasons = (
            invalid_reasons
            + partial_reasons
        )

        # Remove duplicate reasons while preserving order.
        reasons = list(
            dict.fromkeys(
                reasons
            )
        )

        result[
            "preprocess_status"
        ] = status

        result[
            "processing_action"
        ] = action

        result["reason"] = (
            "; ".join(reasons)
            if reasons
            else None
        )

        return result