from email import policy
from email.parser import BytesHeaderParser


def parse_smtp_data(payload: bytes) -> dict | None:
    """Parse a single MIME message in one payload, without stream state."""
    first_line, separator, remainder = payload.partition(b"\n")
    if first_line.strip().upper() == b"DATA":
        if not separator or not remainder.strip():
            return None
        payload = remainder

    if b"\r\n\r\n" in payload:
        header_bytes, body_bytes = payload.split(b"\r\n\r\n", 1)
    elif b"\n\n" in payload:
        header_bytes, body_bytes = payload.split(b"\n\n", 1)
    else:
        header_bytes, body_bytes = payload, None

    message = BytesHeaderParser(policy=policy.default).parsebytes(header_bytes + b"\r\n\r\n")
    headers = {name: str(value) for name, value in message.items()}
    mime_names = {name.lower() for name in headers}
    if not mime_names.intersection({"mime-version", "content-type", "content-transfer-encoding"}):
        return None

    result = {"protocol": "SMTP", "type": "data", "headers": headers, "body": None}
    if body_bytes is not None:
        # Exclude the optional SMTP end-of-DATA line from the MIME body.
        if body_bytes == b".\r\n" or body_bytes == b".\n":
            body_bytes = b""
        elif body_bytes.endswith(b"\r\n.\r\n"):
            body_bytes = body_bytes[:-5]
        elif body_bytes.endswith(b"\n.\n"):
            body_bytes = body_bytes[:-3]
        result["body"] = body_bytes.decode("utf-8", errors="replace")
        try:
            body_bytes.decode("utf-8")
        except UnicodeDecodeError:
            result["raw_body_hex"] = body_bytes.hex()

    if message.get_content_maintype() == "multipart":
        result["mime_parse_reason"] = "Multipart MIME decoding is not supported"
    elif message.defects or any(
        len(message.get_all(name, [])) > 1
        for name in ("Content-Type", "Content-Transfer-Encoding")
    ):
        result["mime_parse_reason"] = "Malformed or duplicate MIME headers"
    return result


def parse_smtp(payload: bytes) -> dict:
    """
    Parse SMTP commands/responses or a complete single-payload MIME message.
    """

    text = payload.decode(
        "utf-8",
        errors="replace",
    )

    lines = text.splitlines()

    if not lines:
        return {
            "protocol": "SMTP",
            "type": "UNKNOWN",
        }

    first_line = lines[0].strip()
    upper_line = first_line.upper()

    data = parse_smtp_data(payload)
    if data is not None:
        return data

    if upper_line == "DATA":
        return {"protocol": "SMTP", "type": "command", "command": "DATA", "argument": ""}


    # SMTP Response
    if (
        len(first_line) >= 3
        and first_line[:3].isdigit()
    ):
        status_code = int(first_line[:3])

        message = ""

        if len(first_line) > 4:
            message = first_line[4:]

        return {
            "protocol": "SMTP",
            "type": "response",
            "status_code": status_code,
            "message": message,
        }


    # HELO
    if upper_line.startswith("HELO "):
        return {
            "protocol": "SMTP",
            "type": "command",
            "command": "HELO",
            "argument": first_line[5:].strip(),
        }


    # EHLO
    if upper_line.startswith("EHLO "):
        return {
            "protocol": "SMTP",
            "type": "command",
            "command": "EHLO",
            "argument": first_line[5:].strip(),
        }

    # MAIL FROM
    if upper_line.startswith("MAIL FROM:"):
        return {
            "protocol": "SMTP",
            "type": "command",
            "command": "MAIL FROM",
            "argument": first_line[10:].strip(),
        }

    # RCPT TO
    if upper_line.startswith("RCPT TO:"):
        return {
            "protocol": "SMTP",
            "type": "command",
            "command": "RCPT TO",
            "argument": first_line[8:].strip(),
        }

    return {
        "protocol": "SMTP",
        "type": "UNKNOWN",
    }
