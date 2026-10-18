import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from decoder.smtp_decoder import decode_smtp_application
from detectors.protocol_detector import detect_application_protocol, is_smtp_payload
from output.jsonl_writer import JSONLWriter
from parsers.smtp_parser import parse_smtp
from pipeline import IDSPipeline
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


EVENTS_PATH = Path(__file__).resolve().parent / "events.jsonl"


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


# The original normalized fixture and all assertions above remain unchanged.
# Each payload below contains one MIME message, without TCP reassembly.
cases = [
    ("base64", b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8gZnJvbSBTTVRQIQ==", "success", "Hello from SMTP!", None),
    ("quoted_printable", b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nHello=20from=20Quoted-Printable=21", "success", "Hello from Quoted-Printable!", None),
    ("mixed_case_data", b"DATA\r\ncOnTeNt-TyPe: text/plain; CHARSET=\"UTF-8\"\r\nCoNtEnT-TrAnSfEr-EnCoDiNg: BaSe64\r\n\r\nSGVsbG8g\r\nZnJvbSBTTVRQIQ==\r\n.\r\n", "success", "Hello from SMTP!", None),
    ("folded_header", b"From: alice@example.com\r\nMIME-Version: 1.0\r\nContent-Type: text/plain;\r\n charset=utf-8\r\nContent-Transfer-Encoding:\r\n quoted-printable\r\n\r\nXin=20ch=C3=A0o", "success", "Xin ch\u00e0o", None),
    ("no_encoding", b"Content-Type: text/plain\r\n\r\nSGVsbG8=", "unchanged", None, None),
    ("missing_body", b"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64", "partial", None, "body is missing"),
    ("empty_body", b"Content-Transfer-Encoding: base64\r\n\r\n", "partial", None, "body is missing"),
    ("bad_base64", b"Content-Transfer-Encoding: base64\r\n\r\nNOT-BASE64!!!", "partial", None, "Error"),
    ("bad_qp", b"Content-Transfer-Encoding: quoted-printable\r\n\r\nHello=GG", "partial", None, "Invalid Quoted-Printable"),
    ("unknown_charset", b"Content-Type: text/plain; charset=unknown-test-charset\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8=", "partial", "Hello", "Unsupported MIME charset"),
    ("invalid_utf8", b"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n/w==", "partial", "\ufffd", "Invalid UTF-8"),
    ("invalid_ascii", b"Content-Type: text/plain; charset=us-ascii\r\nContent-Transfer-Encoding: base64\r\n\r\n/w==", "partial", "\ufffd", "Invalid MIME charset data"),
    ("latin1", b"Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nCaf=E9", "success", "Caf\u00e9", None),
    ("invalid_raw_bytes", b"Content-Transfer-Encoding: base64\r\n\r\n\xff", "partial", None, "Error"),
    ("unsupported_encoding", b"Content-Transfer-Encoding: x-custom\r\n\r\nSGVsbG8=", "unchanged", None, "Unsupported Content-Transfer-Encoding"),
    ("duplicate_headers", b"Content-Transfer-Encoding: base64\r\ncontent-transfer-encoding: quoted-printable\r\n\r\nSGVsbG8=", "partial", None, "Malformed or duplicate MIME headers"),
    ("multipart", b"Content-Type: multipart/mixed; boundary=test\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8=", "partial", None, "Multipart MIME"),
    ("lf_only", b"MIME-Version: 1.0\nContent-Transfer-Encoding: quoted-printable\n\nHello=20world=21\n.\n", "success", "Hello world!", None),
]
packet_events = []
for index, (name, payload, status, expected_body, reason) in enumerate(cases):
    parsed = parse_smtp(payload)
    assert parsed["type"] == "data", name
    assert parsed["headers"], name
    assert is_smtp_payload(payload), name
    port = 2525 if name == "mixed_case_data" else 25
    assert detect_application_protocol("TCP", 50000, port, payload) == "SMTP", name
    json.dumps(parsed, ensure_ascii=False)
    direct = decode_smtp_application(parsed, 65536)
    packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=50000, dport=port, flags="PA") / Raw(load=payload)
    packet = IP(bytes(packet))
    packet.time = 1790000200.0 + index
    event = IDSPipeline().process_packet(packet, index + 1)
    assert event is not None, name
    assert event["errors"] == [], name
    assert event["application"]["protocol"] == "SMTP", name
    assert event["application"]["type"] == "data", name
    assert event["decoder"]["status"] == status, (name, event)
    assert event["preprocess_status"] == ("partial" if status == "partial" else "valid"), name
    for app in (direct, event["application"]):
        assert app["decode_status"] == status, (name, app)
        assert app["body"] == parsed["body"], name
        if parsed["body"] is not None:
            assert app["raw_body"] == parsed["body"], name
        if expected_body is not None:
            assert app["decoded_body"] == expected_body, (name, app)
        else:
            assert "decoded_body" not in app, name
        if reason is not None:
            assert reason in app["decode_reason"], (name, app)
        else:
            assert app["decode_reason"] is None, name
        assert json.loads(json.dumps(app, ensure_ascii=False)) == app
    if "raw_body_hex" in parsed:
        assert event["application"]["raw_body_hex"] == parsed["raw_body_hex"]
    packet_events.append(event)
    print(f"T03 packet/{name}: {status} PASS")

assert parse_smtp(b"DATA\r\n")["command"] == "DATA"
assert parse_smtp(b"\r\n")["type"] == "UNKNOWN"
assert not is_smtp_payload(b"")
assert not is_smtp_payload(b"\n")
assert not is_smtp_payload(b"arbitrary body without MIME headers")

# Normalized-event safety and size limits, including the direct-bytes API.
for body in (None, "", 123, {"invalid": True}, b"\xff"):
    decoded = decode_smtp_application({"protocol": "SMTP", "headers": {"Content-Transfer-Encoding": "base64"}, "body": body}, 65536)
    assert decoded["decode_status"] == "partial"
    assert decoded["decode_reason"]
    json.dumps(decoded)
decoded = decode_smtp_application({"headers": {"Content-Transfer-Encoding": "base64"}, "body": b"SGVsbG8="}, 65536)
assert decoded["decoded_body"] == "Hello"
json.dumps(decoded)
decoded = decode_smtp_application({"headers": {}, "body": b"SGVsbG8="}, 65536)
assert decoded["decode_status"] == "unchanged"
assert "decoded_body" not in decoded
json.dumps(decoded)
decoded = decode_smtp_application({"headers": {"Content-Transfer-Encoding": "base64"}, "body": "SGVsbG8="}, 2)
assert decoded["decode_status"] == "partial"
assert "size limit" in decoded["decode_reason"]
decoded = decode_smtp_application({"headers": {"Content-Type": "text/plain; charset=idna", "Content-Transfer-Encoding": "base64"}, "body": "/w=="}, 65536)
assert decoded["decode_status"] == "partial"
assert decoded["decode_reason"]
json.dumps(decoded)

packet_path = EVENTS_PATH.with_name("packet_events.jsonl")
with JSONLWriter(str(packet_path)) as writer:
    for event in packet_events:
        writer.write_event(event)
assert [json.loads(line) for line in packet_path.read_text(encoding="utf-8").splitlines()] == packet_events
print("T03 original normalized fixture and packet pipeline/JSONL PASS")
print("T03 PASS")
