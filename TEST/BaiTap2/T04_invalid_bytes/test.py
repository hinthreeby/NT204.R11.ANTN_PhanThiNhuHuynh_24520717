import json
import sys
from pathlib import Path


# Allow direct execution from any working directory.
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from config import IDSConfig
from decoder.decoder import Decoder
from decoder.http_decoder import decode_http_application
from output.jsonl_writer import JSONLWriter
from parsers.http_parser import parse_http
from parsers.packet_parser import process_packet
from pipeline import IDSPipeline
from preprocessor.preprocessor import Preprocessor
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


event = {
    "packet_id": 1,
    "timestamp": 1790000003.0,

    "network": {
        "protocol": "IPv4",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
    },

    "transport": {
        "protocol": "TCP",
        "src_port": 50000,
        "dst_port": 80,
    },

    "application": {
        "protocol": "HTTP",
        "type": "response",
        "headers": {
            "Content-Type": "text/plain"
        },
        "body": b"Hello \xff world",
    },

    "errors": [],
}


decoder = Decoder(
    IDSConfig()
)


result = decoder.process(
    event
)


application = result[
    "application"
]


assert (
    application["decode_status"]
    == "partial"
)

assert (
    "\ufffd"
    in application["decoded_body"]
)


print(
    json.dumps(
        result,
        indent=2,
        ensure_ascii=False,
    )
)

# Keep the original direct-bytes test above, then exercise actual HTTP packets.
packet_events = []
cases = [
    ("ascii", b"Hello world", "Hello world", "success"),
    ("utf8", "Xin ch\u00e0o".encode("utf-8"), "Xin ch\u00e0o", "success"),
    ("invalid_ff", b"Hello \xff world", "Hello \ufffd world", "partial"),
    ("truncated_utf8", b"Hello \xc3", "Hello \ufffd", "partial"),
    # A literal replacement character is valid UTF-8, not evidence of byte loss.
    ("valid_replacement", "Hello \ufffd".encode("utf-8"), "Hello \ufffd", "success"),
]
for kind in ("request", "response"):
    for name, raw_body, expected_text, status in cases:
        start_line = b"POST /submit?q=%27 HTTP/1.1" if kind == "request" else b"HTTP/1.1 200 OK"
        payload = (
            start_line + b"\r\nHost: example.com\r\nContent-Type: text/plain; charset=utf-8\r\n"
            + f"Content-Length: {len(raw_body)}\r\n\r\n".encode("ascii") + raw_body
        )
        parsed_application = parse_http(payload)
        assert parsed_application["type"] == kind
        assert parsed_application["body"] == expected_text
        json.dumps(parsed_application, ensure_ascii=False)
        if status == "partial":
            assert bytes.fromhex(parsed_application["raw_body_hex"]) == raw_body
        else:
            assert "raw_body_hex" not in parsed_application

        packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=50000, dport=80, flags="PA") / Raw(load=payload)
        packet = IP(bytes(packet))
        packet.time = 1790000010.0 + len(packet_events)
        packet_id = len(packet_events) + 1
        parsed_event = process_packet(packet, packet_id)
        assert parsed_event["errors"] == []
        assert parsed_event["application"] == parsed_application
        json.dumps(parsed_event, ensure_ascii=False)
        decoded_event = decoder.process(parsed_event)
        processed_event = Preprocessor(IDSConfig()).process(decoded_event)
        final_event = IDSPipeline().process_packet(packet, packet_id)
        assert final_event is not None

        for checked in (decoded_event, processed_event, final_event):
            application = checked["application"]
            assert application["body"] == expected_text
            assert application["decoded_text"] == expected_text
            assert application["decode_status"] == status
            assert checked["decoder"]["status"] == status
            if kind == "request":
                assert application["raw_uri"] == "/submit?q=%27"
                assert application["decoded_uri"] == "/submit?q='"
            if status == "partial":
                assert application["raw_body_hex"] == raw_body.hex()
                assert application["decoded_body"] == expected_text
                assert "Invalid UTF-8 byte sequence" in application["decode_reason"]
                assert checked["decoder"]["reason"] == application["decode_reason"]
            else:
                assert application["decode_reason"] is None
            assert json.loads(json.dumps(checked, ensure_ascii=False)) == checked

        for checked in (processed_event, final_event):
            assert checked["preprocess_status"] == ("partial" if status == "partial" else "valid")
            assert checked["processing_action"] == "continue"
            if status == "partial":
                assert "Decoder reported partial result" in checked["reason"]
        packet_events.append(final_event)
        print(f"T04 {kind}/{name}: decoder={status}, preprocess={final_event['preprocess_status']} PASS")

# Invalid header bytes must not disappear either (BaiTap1 decode_error schema).
for start_line in (b"GET / HTTP/1.1", b"HTTP/1.1 200 OK"):
    raw_header = start_line + b"\r\nContent-Type: text/plain\r\nX-Test: \xff"
    payload = raw_header + b"\r\n\r\nHello"
    packet = IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=50000, dport=80, flags="PA") / Raw(load=payload)
    packet = IP(bytes(packet))
    packet.time = 1790000010.0 + len(packet_events)
    header_event = IDSPipeline().process_packet(packet, len(packet_events) + 1)
    assert header_event is not None
    assert header_event["application"]["raw_header_hex"] == raw_header.hex()
    assert header_event["application"]["body"] == "Hello"
    assert header_event["decoder"]["status"] == "partial"
    assert "HTTP header: Invalid UTF-8 byte sequence" in header_event["decoder"]["reason"]
    assert header_event["preprocess_status"] == "partial"
    packet_events.append(header_event)
print("T04 invalid HTTP request/response header bytes PASS")

# LF-only messages and malformed hex metadata also remain safe and serializable.
lf_application = parse_http(b"HTTP/1.1 200 OK\nContent-Type: text/plain\n\nHi \xff")
assert lf_application["raw_body_hex"] == b"Hi \xff".hex()
assert decode_http_application(lf_application)["decode_status"] == "partial"
for invalid_hex in (None, "not-hex", 123):
    malformed = decode_http_application({"protocol": "HTTP", "body": "Hello", "raw_body_hex": invalid_hex})
    assert malformed["decode_status"] == "partial"
    assert "Invalid raw_body_hex" in malformed["decode_reason"]
    json.dumps(malformed)
for malformed_payload in (b"", b"bad start\r\n\r\n\xff", b"HTTP/1.1 bad\r\n\r\n\xff"):
    malformed = decode_http_application(parse_http(malformed_payload))
    json.dumps(malformed)
    assert malformed["decode_status"] == ("partial" if b"\xff" in malformed_payload else "success")

events_path = Path(__file__).resolve().with_name("events.jsonl")
with JSONLWriter(str(events_path)) as writer:
    for packet_event in packet_events:
        writer.write_event(packet_event)
assert [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()] == packet_events
print("T04 Parser -> Decoder -> Preprocessor -> Flow Tracker and JSONL round-trip PASS")
print("T04 PASS")
