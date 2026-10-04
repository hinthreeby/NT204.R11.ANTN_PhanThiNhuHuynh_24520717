from copy import deepcopy
from html import unescape
from urllib.parse import unquote, unquote_plus

from decoder.character_decoder import (
    decode_character_data,
)


def get_header_value(
    headers: dict,
    target_name: str,
) -> str | None:
    """
    Get an HTTP header value using a case-insensitive name.
    """

    target_name = target_name.lower()

    for name, value in headers.items():
        if str(name).lower() == target_name:
            return str(value)

    return None


def decode_http_application(
    application: dict,
) -> dict:
    """
    Decode HTTP application data while preserving raw values.
    """

    result = deepcopy(application)

    decode_status = "success"
    reasons = []

    # URL / Percent decoding
    uri = result.get("uri")

    if isinstance(uri, str):
        result["raw_uri"] = uri

        result["decoded_uri"] = unquote(
            uri,
            encoding="utf-8",
            errors="replace",
        )


    # HTTP headers
    headers = result.get(
        "headers",
        {}
    )

    if not isinstance(headers, dict):
        headers = {}

    content_type = get_header_value(
        headers,
        "Content-Type",
    )

    if content_type is None:
        content_type = ""

    # Character decoding
    body = result.get("body")

    body_text = None

    if isinstance(
        body,
        (bytes, bytearray),
    ):
        result["raw_body_hex"] = (
            bytes(body).hex()
        )

        character_result = (
            decode_character_data(
                body
            )
        )

        body_text = character_result[
            "text"
        ]

        # Keep the event JSON-compatible.
        result["body"] = body_text

        result["decoded_body"] = (
            body_text
        )

        result["character_encoding"] = (
            character_result["encoding"]
        )

        if (
            character_result["status"]
            == "partial"
        ):
            decode_status = "partial"

            if character_result["reason"]:
                reasons.append(
                    character_result["reason"]
                )

    elif isinstance(body, str):
        result["raw_body"] = body
        body_text = body

    # Form URL decoding
    if (
        body_text is not None
        and
        "application/x-www-form-urlencoded"
        in content_type.lower()
    ):
        result["decoded_body"] = (
            unquote_plus(
                body_text,
                encoding="utf-8",
                errors="replace",
            )
        )

    # HTML entity decoding
    if (
        body_text is not None
        and content_type.lower().startswith(
            "text/"
        )
    ):
        result["decoded_text"] = (
            unescape(
                body_text
            )
        )

    # Decode metadata
    result["decode_status"] = (
        decode_status
    )

    result["decode_reason"] = (
        "; ".join(reasons)
        if reasons
        else None
    )

    return result