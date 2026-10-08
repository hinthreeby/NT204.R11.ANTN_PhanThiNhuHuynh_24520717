def parse_smtp(payload: bytes) -> dict:
    """
    Parse an SMTP command or response.
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