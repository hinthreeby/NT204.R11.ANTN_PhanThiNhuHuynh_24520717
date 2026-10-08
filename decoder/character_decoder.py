def decode_character_data(
    value,
) -> dict:
    """
    Decode text data using ASCII or UTF-8.

    Invalid UTF-8 byte sequences are replaced instead of
    raising an exception.
    """

    if value is None:
        return {
            "text": None,
            "encoding": None,
            "status": "unchanged",
            "reason": None,
        }

    if isinstance(value, str):
        return {
            "text": value,
            "encoding": "unicode",
            "status": "success",
            "reason": None,
        }

    if not isinstance(
        value,
        (bytes, bytearray),
    ):
        return {
            "text": str(value),
            "encoding": None,
            "status": "partial",
            "reason": (
                "Unsupported value type converted "
                "to string"
            ),
        }

    raw_data = bytes(value)

    # -------------------------
    # ASCII
    # -------------------------

    try:
        decoded_text = raw_data.decode(
            "ascii"
        )

        return {
            "text": decoded_text,
            "encoding": "ascii",
            "status": "success",
            "reason": None,
        }

    except UnicodeDecodeError:
        pass

    # -------------------------
    # UTF-8
    # -------------------------

    try:
        decoded_text = raw_data.decode(
            "utf-8"
        )

        return {
            "text": decoded_text,
            "encoding": "utf-8",
            "status": "success",
            "reason": None,
        }

    except UnicodeDecodeError as exc:
        decoded_text = raw_data.decode(
            "utf-8",
            errors="replace",
        )

        return {
            "text": decoded_text,
            "encoding": "utf-8",
            "status": "partial",
            "reason": (
                "Invalid UTF-8 byte sequence: "
                f"{exc}"
            ),
        }