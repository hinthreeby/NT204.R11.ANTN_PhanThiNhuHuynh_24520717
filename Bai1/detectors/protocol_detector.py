HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
)

HTTP_RESPONSE_PREFIXES = (
    b"HTTP/1.0 ",
    b"HTTP/1.1 ",
)

HTTP_STANDARD_PORTS = {80}


def is_http_payload(payload: bytes) -> bool:
    """
    Check whether a TCP payload looks like HTTP/1.x.
    """

    if not payload:
        return False

    # HTTP request
    if payload.startswith(HTTP_METHODS):
        return True

    # HTTP response
    if payload.startswith(HTTP_RESPONSE_PREFIXES):
        return True

    return False


def detect_application_protocol(
    transport_protocol: str,
    src_port: int | None,
    dst_port: int | None,
    payload: bytes,
) -> str:
    """
    Detect the application protocol using both
    port information and payload signatures.

    Currently supported:
    - HTTP/1.x

    DNS and SMTP will be added later.
    """

    if transport_protocol != "TCP":
        return "UNKNOWN"

    if not payload:
        return "UNKNOWN"

    uses_standard_http_port = (
        src_port in HTTP_STANDARD_PORTS
        or dst_port in HTTP_STANDARD_PORTS
    )

    # Standard HTTP port + valid HTTP payload
    if uses_standard_http_port and is_http_payload(payload):
        return "HTTP"

    # Payload-based detection allows HTTP on non-standard ports
    if is_http_payload(payload):
        return "HTTP"

    return "UNKNOWN"