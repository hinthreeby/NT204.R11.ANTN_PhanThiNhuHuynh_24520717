import json
from pathlib import Path


EVENTS_PATH = Path(
    "TEST/T03_smtp_mime/events.jsonl"
)


with EVENTS_PATH.open(
    mode="r",
    encoding="utf-8",
) as file:
    events = [
        json.loads(line)
        for line in file
        if line.strip()
    ]


assert len(events) == 2


# -------------------------
# Base64
# -------------------------

base64_event = events[0]

base64_application = (
    base64_event["application"]
)

assert (
    base64_application[
        "content_transfer_encoding"
    ]
    == "base64"
)

assert (
    base64_application[
        "decoded_body"
    ]
    == "Hello from SMTP!"
)

assert (
    base64_application[
        "decode_status"
    ]
    == "success"
)

assert (
    base64_event["decoder"]["status"]
    == "success"
)


# -------------------------
# Quoted-Printable
# -------------------------

qp_event = events[1]

qp_application = (
    qp_event["application"]
)

assert (
    qp_application[
        "content_transfer_encoding"
    ]
    == "quoted-printable"
)

assert (
    qp_application[
        "decoded_body"
    ]
    == "Hello from Quoted-Printable!"
)

assert (
    qp_application[
        "decode_status"
    ]
    == "success"
)

assert (
    qp_event["decoder"]["status"]
    == "success"
)


print("T03 PASS")