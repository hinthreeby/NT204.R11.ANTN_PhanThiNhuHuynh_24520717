HTTP_METHODS = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "OPTIONS",
}


def split_http_message(text: str) -> tuple[str, str]:
    """
    Split an HTTP message into:
    - header section
    - body
    """

    if "\r\n\r\n" in text:
        return text.split("\r\n\r\n", 1)

    if "\n\n" in text:
        return text.split("\n\n", 1)

    return text, ""


def parse_headers(lines: list[str]) -> dict:
    """
    Parse HTTP header lines into a dictionary.
    """

    headers = {}

    for line in lines:
        if ":" not in line:
            continue

        name, value = line.split(":", 1)

        headers[name.strip()] = value.strip()

    return headers


def parse_http(payload: bytes) -> dict:
    """
    Parse an HTTP/1.x request or response from TCP payload.
    """

    text = payload.decode(
        "utf-8",
        errors="replace"
    )

    header_section, body = split_http_message(text)

    lines = header_section.splitlines()

    if not lines:
        return {
            "protocol": "HTTP",
            "type": "UNKNOWN",
        }

    start_line = lines[0]
    header_lines = lines[1:]

    headers = parse_headers(header_lines)

    # HTTP response
    if start_line.startswith("HTTP/1."):
        parts = start_line.split(" ", 2)

        version = parts[0]

        status_code = None
        if len(parts) >= 2:
            try:
                status_code = int(parts[1])
            except ValueError:
                status_code = None

        reason = parts[2] if len(parts) >= 3 else ""

        return {
            "protocol": "HTTP",
            "type": "response",
            "version": version,
            "status_code": status_code,
            "reason": reason,
            "headers": headers,
            "body": body,
        }

    # HTTP request
    parts = start_line.split(" ", 2)

    if len(parts) == 3:
        method, uri, version = parts

        if method in HTTP_METHODS:
            return {
                "protocol": "HTTP",
                "type": "request",
                "method": method,
                "uri": uri,
                "version": version,
                "headers": headers,
                "body": body,
            }

    return {
        "protocol": "HTTP",
        "type": "UNKNOWN",
        "headers": headers,
        "body": body,
    }