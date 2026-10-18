import base64
import binascii
import quopri
import re

from copy import deepcopy
from email.message import Message

from decoder.character_decoder import (
    decode_character_data,
)


def get_header_value(
    headers: dict,
    target_name: str,
) -> str | None:
    """
    Get a MIME header value using a case-insensitive name.
    """

    target_name = target_name.lower()

    for name, value in headers.items():
        if str(name).lower() == target_name:
            return str(value)

    return None


def decode_base64_body(
    body: bytes,
) -> bytes:
    """
    Decode a Base64 MIME body.
    """

    # MIME Base64 may contain line breaks.
    compact_body = b"".join(
        body.split()
    )

    return base64.b64decode(
        compact_body,
        validate=True,
    )


def decode_quoted_printable_body(
    body: bytes,
) -> bytes:
    """
    Decode a Quoted-Printable MIME body.
    """

    if re.search(rb"=(?![0-9a-fA-F]{2}|\r?\n)", body):
        raise ValueError("Invalid Quoted-Printable escape")

    return quopri.decodestring(
        body
    )


def decode_smtp_application(
    application: dict,
    max_decode_size: int,
) -> dict:
    """
    Decode SMTP/MIME application data while preserving
    the original body.

    Supported Content-Transfer-Encoding values:
    - base64
    - quoted-printable
    """

    result = deepcopy(
        application
    )

    result["decode_status"] = (
        "unchanged"
    )

    result["decode_reason"] = None

    body = result.get("body")
    if isinstance(body, (bytes, bytearray)):
        result["raw_body_hex"] = bytes(body).hex()
        result["body"] = bytes(body).decode("utf-8", errors="replace")
    elif isinstance(body, str):
        result["raw_body"] = body

    if result.get("mime_parse_reason"):
        result["decode_status"] = "partial"
        result["decode_reason"] = result["mime_parse_reason"]
        return result

    headers = result.get(
        "headers",
        {}
    )

    if not isinstance(
        headers,
        dict,
    ):
        headers = {}

    transfer_encoding = get_header_value(
        headers,
        "Content-Transfer-Encoding",
    )

    # Do not decode MIME data unless the header
    # explicitly specifies an encoding.
    if transfer_encoding is None:
        return result

    transfer_encoding = (
        transfer_encoding
        .strip()
        .lower()
    )

    result[
        "content_transfer_encoding"
    ] = transfer_encoding

    if body is None or body == "" or body == b"":
        result["decode_status"] = (
            "partial"
        )

        result["decode_reason"] = (
            "MIME encoding specified but "
            "body is missing"
        )

        return result

    # Preserve raw body
    if isinstance(body, str):
        result["raw_body"] = body

        body_bytes = body.encode(
            "utf-8"
        )

    elif isinstance(
        body,
        (bytes, bytearray),
    ):
        body_bytes = bytes(
            body
        )

        result["raw_body_hex"] = (
            body_bytes.hex()
        )

    else:
        result["decode_status"] = (
            "partial"
        )

        result["decode_reason"] = (
            "Unsupported MIME body type"
        )

        return result

    if "raw_body_hex" in result:
        try:
            body_bytes = bytes.fromhex(result["raw_body_hex"])
        except (TypeError, ValueError):
            result["decode_status"] = "partial"
            result["decode_reason"] = "Invalid raw_body_hex in MIME data"
            return result

    content_type = get_header_value(headers, "Content-Type")
    mime = Message()
    if content_type is not None:
        mime["Content-Type"] = content_type
    if mime.get_content_maintype() == "multipart":
        result["decode_status"] = "partial"
        result["decode_reason"] = "Multipart MIME decoding is not supported"
        return result

    # Size limit
    if len(body_bytes) > max_decode_size:
        result["decode_status"] = (
            "partial"
        )

        result["decode_reason"] = (
            "MIME body exceeds configured "
            "decode size limit"
        )

        return result

    # -------------------------
    # Content-Transfer-Encoding
    # -------------------------

    try:
        if transfer_encoding == "base64":
            decoded_bytes = (
                decode_base64_body(
                    body_bytes
                )
            )

        elif (
            transfer_encoding
            == "quoted-printable"
        ):
            decoded_bytes = (
                decode_quoted_printable_body(
                    body_bytes
                )
            )

        else:
            result["decode_status"] = (
                "unchanged"
            )

            result["decode_reason"] = (
                "Unsupported "
                "Content-Transfer-Encoding: "
                f"{transfer_encoding}"
            )

            return result

    except (
        ValueError,
        binascii.Error,
    ) as exc:
        result["decode_status"] = (
            "partial"
        )

        result["decode_reason"] = (
            f"{type(exc).__name__}: "
            f"{exc}"
        )

        return result

    # Character decoding
    character_result = (
        decode_character_data(
            decoded_bytes
        )
    )

    charset = mime.get_content_charset()
    if charset is not None and charset.replace("_", "-") not in {"utf-8", "utf8"}:
        try:
            character_result = {
                "text": decoded_bytes.decode(charset),
                "encoding": charset,
                "status": "success",
                "reason": None,
            }
        except LookupError:
            character_result["status"] = "partial"
            character_result["reason"] = f"Unsupported MIME charset: {charset}"
        except UnicodeError as exc:
            try:
                replacement_text = decoded_bytes.decode(charset, errors="replace")
            except (LookupError, UnicodeError):
                replacement_text = character_result["text"]
            character_result = {
                "text": replacement_text,
                "encoding": charset,
                "status": "partial",
                "reason": f"Invalid MIME charset data ({charset}): {exc}",
            }

    result["decoded_body"] = (
        character_result["text"]
    )

    result["character_encoding"] = (
        character_result["encoding"]
    )

    if (
        character_result["status"]
        == "partial"
    ):
        result["decode_status"] = (
            "partial"
        )

        result["decode_reason"] = (
            character_result["reason"]
        )

    else:
        result["decode_status"] = (
            "success"
        )

        result["decode_reason"] = None

    return result
