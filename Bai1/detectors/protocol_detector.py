from scapy.layers.dns import DNS, DNSQR, DNSRR
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

DNS_STANDARD_PORTS = {53}
HTTP_STANDARD_PORTS = {80}

SMTP_STANDARD_PORTS = {
    25,
    587,
}

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
    Detect application protocol using transport information,
    ports, and payload signatures.
    """

    if not payload:
        return "UNKNOWN"

    # TCP application protocols

    if transport_protocol == "TCP":
        uses_standard_http_port = (
            src_port in HTTP_STANDARD_PORTS
            or dst_port in HTTP_STANDARD_PORTS
        )

        if uses_standard_http_port and is_http_payload(payload):
            return "HTTP"

        # Payload-based detection also supports
        # HTTP on non-standard ports.
        if is_http_payload(payload):
            return "HTTP"
        
        uses_standard_smtp_port = (
            src_port in SMTP_STANDARD_PORTS
            or dst_port in SMTP_STANDARD_PORTS
        )

        if uses_standard_smtp_port and is_smtp_payload(payload):
            return "SMTP"

        # Payload-based detection also allows SMTP
        # on non-standard ports.
        if is_smtp_payload(payload):
            return "SMTP"

    # UDP application protocols
    elif transport_protocol == "UDP":
        uses_standard_dns_port = (
            src_port in DNS_STANDARD_PORTS
            or dst_port in DNS_STANDARD_PORTS
        )

        if uses_standard_dns_port and is_dns_payload(payload):
            return "DNS"

    return "UNKNOWN"

def is_dns_payload(payload: bytes) -> bool:
    """
    Check whether a UDP payload is a structurally valid DNS message.
    """

    if not payload or len(payload) < 12:
        return False

    try:
        dns = DNS(payload)
    except Exception:
        return False

    # DNS query
    if int(dns.qr) == 0:
        if int(dns.qdcount or 0) < 1:
            return False

        try:
            question = dns.qd[0]
        except (TypeError, IndexError, KeyError):
            question = dns.qd

        return isinstance(question, DNSQR)

    # DNS response
    if int(dns.qr) == 1:
        # A response should normally contain a valid question
        # or at least one valid answer.
        if int(dns.qdcount or 0) > 0:
            try:
                question = dns.qd[0]
            except (TypeError, IndexError, KeyError):
                question = dns.qd

            if isinstance(question, DNSQR):
                return True

        if int(dns.ancount or 0) > 0:
            try:
                answer = dns.an[0]
            except (TypeError, IndexError, KeyError):
                answer = dns.an

            if isinstance(answer, DNSRR):
                return True

    return False

def is_smtp_payload(payload: bytes) -> bool:
    """
    Check whether a TCP payload looks like SMTP.
    """

    if not payload:
        return False

    first_line = payload.splitlines()[0].strip()

    upper_line = first_line.upper()

    smtp_commands = (
        b"HELO ",
        b"EHLO ",
        b"MAIL FROM:",
        b"RCPT TO:",
        b"DATA",
        b"QUIT",
        b"RSET",
        b"NOOP",
    )

    if upper_line.startswith(smtp_commands):
        return True

    # SMTP responses start with a 3-digit status code.
    # Examples: 220 Service ready, 250 OK, 550 Requested action not taken

    if (
        len(first_line) >= 3
        and first_line[:3].isdigit()
    ):
        if len(first_line) == 3:
            return True

        if first_line[3:4] in (b" ", b"-"):
            return True

    return False