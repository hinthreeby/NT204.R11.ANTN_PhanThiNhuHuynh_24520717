"""Verify TCP flags and transport payload size matching for T12."""

from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import json
import sys


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parents[2]))

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from core_engine.models import MatchResult
from core_engine.packet_matcher import PacketMatcher
from core_engine.rule_loader import RuleLoader
from core_engine.rule_parser import RuleParserValidator
from parsers.packet_parser import process_packet
from pipeline import IDSPipeline


INPUT = TEST_DIR / "sample.rules"


def parsed_event(flags="A", payload=b"", udp=False) -> dict:
    """Parse a serialized packet with the real Bài 1 parser."""

    layer = UDP(sport=50000, dport=443) if udp else TCP(sport=50000, dport=443, flags=flags)
    packet = IP(src="192.168.1.10", dst="192.168.1.20") / layer
    if payload:
        packet = packet / Raw(load=payload)
    packet = IP(bytes(packet))
    packet.time = 1000.0
    normalized = process_packet(packet, 1)
    assert isinstance(normalized, dict)
    assert normalized["transport"]["payload_hex"] == payload.hex()
    assert bytes.fromhex(normalized["transport"]["payload_hex"]) == payload
    assert normalized["transport"]["payload_length"] == len(payload)
    assert normalized["network"]["total_length"] == (28 if udp else 40) + len(payload)
    assert json.loads(json.dumps(normalized)) == normalized
    return normalized


def changed(normalized: dict, **fields) -> dict:
    """Change transport fields in a copied malformed fixture."""

    copied = deepcopy(normalized)
    copied["transport"].update(fields)
    return copied


def main() -> None:
    """Run fixed positive and negative packet-option assertions."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")

    original = INPUT.read_bytes()
    loader = RuleLoader()
    results = [RuleParserValidator().parse(source) for source in loader.load([INPUT])]
    assert len(results) == 17 and not loader.issues
    assert all(result.status == "valid" for result in results)
    rules = {result.rule.sid: result.rule for result in results}
    assert set(rules) == set(range(101201, 101218))
    snapshot = {sid: asdict(rule) for sid, rule in rules.items()}
    syn, syn_ack, ack = parsed_event("S"), parsed_event("SA"), parsed_event("A")
    assert syn["transport"]["flags"] == ["SYN"]
    assert syn_ack["transport"]["flags"] == ["SYN", "ACK"]
    assert ack["transport"]["flags"] == ["ACK"]
    nine, ten, eleven = (parsed_event("A", b"x" * size) for size in (9, 10, 11))
    udp = parsed_event(payload=b"\x00\xff\x80", udp=True)
    cases = [
        ("SYN exact", 1, syn, "MATCH", None),
        ("SYN ACK exact", 5, syn_ack, "MATCH", None),
        ("SYN ACK is not SYN only", 1, syn_ack, "NO_MATCH", None),
        ("SYN is not SYN ACK", 5, syn, "NO_MATCH", None),
        ("ACK exact", 6, ack, "MATCH", None),
        ("ACK is not SYN", 1, ack, "NO_MATCH", None),
        ("UDP cannot match TCP flags", 1, udp, "NO_MATCH", None),
        ("empty payload", 2, syn, "MATCH", None),
        ("exactly ten bytes", 8, ten, "MATCH", None),
        ("ten is not greater than ten", 3, ten, "NO_MATCH", None),
        ("eleven greater than ten", 3, eleven, "MATCH", None),
        ("nine less than ten", 7, nine, "MATCH", None),
        ("ten is not less than ten", 7, ten, "NO_MATCH", None),
        ("range lower boundary excluded", 9, ten, "NO_MATCH", None),
        ("range first interior byte", 9, eleven, "MATCH", None),
        ("range last interior byte", 9, parsed_event(payload=b"x" * 19), "MATCH", None),
        ("range upper boundary excluded", 9, parsed_event(payload=b"x" * 20), "NO_MATCH", None),
        ("range above upper boundary", 9, parsed_event(payload=b"x" * 21), "NO_MATCH", None),
        ("flags and size true", 4, eleven, "MATCH", None),
        ("flags true size false", 4, ten, "NO_MATCH", None),
        ("size true flags false", 4, parsed_event("S", b"x" * 11), "NO_MATCH", None),
        ("flags and size false", 4, syn, "NO_MATCH", None),
        ("UDP dsize", 17, udp, "MATCH", None),
        ("valid zero flags", 10, parsed_event(0), "MATCH", None),
        ("SYN is not zero flags", 10, syn, "NO_MATCH", None),
    ]
    for flag, suffix in (("F", 11), ("R", 12), ("P", 13), ("U", 14), ("C", 15), ("E", 16)):
        cases.append((f"flag {flag} exact", suffix, parsed_event(flag), "MATCH", None))
        cases.append((f"flag {flag} does not match ACK", suffix, ack, "NO_MATCH", None))
    for value in (None, "SYN", ["S"], ["SYN", "SYN"], [1], {}):
        cases.append((f"malformed flags {value}", 1, changed(syn, flags=value), "NO_MATCH", None))
    missing_flags = deepcopy(syn)
    del missing_flags["transport"]["flags"]
    cases.extend([
        ("missing flags not SYN", 1, missing_flags, "NO_MATCH", None),
        ("missing flags not zero", 10, missing_flags, "NO_MATCH", None),
    ])
    for size in (None, -1, True, "10", 1.5):
        cases.append((f"invalid size {size}", 8, changed(ten, payload_length=size), "NO_MATCH", "payload_length"))
    missing_size = deepcopy(ten)
    del missing_size["transport"]["payload_length"]
    length_only = deepcopy(ten)
    del length_only["transport"]["payload_hex"]
    missing_both = deepcopy(missing_size)
    del missing_both["transport"]["payload_hex"]
    cases.extend([
        ("hex fallback when size missing", 8, missing_size, "MATCH", None),
        ("legacy length without hex", 8, length_only, "MATCH", None),
        ("both payload fields missing", 2, missing_both, "NO_MATCH", "Missing"),
        ("length conflicts with hex", 8, changed(ten, payload_hex="ff"), "NO_MATCH", "conflicts"),
        ("invalid hex", 8, changed(ten, payload_hex="not-hex"), "NO_MATCH", "payload_hex"),
        ("odd hex", 8, changed(ten, payload_hex="f"), "NO_MATCH", "payload_hex"),
    ])
    binary = parsed_event(payload=b"\x00\xff\x80abcdefg")
    utf8_payload = "ééééé".encode("utf-8")
    assert len(utf8_payload) == 10 and len(utf8_payload.decode("utf-8")) == 5
    cases.extend([
        ("binary ten bytes", 8, binary, "MATCH", None),
        ("UTF-8 ten bytes not five characters", 8, parsed_event(payload=utf8_payload), "MATCH", None),
        ("IPv4 length is not dsize zero", 2, ten, "NO_MATCH", None),
    ])
    counters = deepcopy(ten)
    counters["network"]["total_length"] = 0
    counters["flow"] = {"byte_count": 0, "SYN_count": 1000, "ACK_count": 0}
    counters["application"]["decoded_body"] = ""
    cases.extend([
        ("dsize ignores IP/flow/application lengths", 8, counters, "MATCH", None),
        ("flags ignores SYN counter", 1, counters, "NO_MATCH", None),
        ("flags uses current ACK not ACK counter", 6, counters, "MATCH", None),
    ])
    pipeline_event = IDSPipeline().process_event(eleven)
    assert pipeline_event is not None and pipeline_event["flow"]["tracked"] is True
    assert pipeline_event["transport"] == eleven["transport"]
    assert pipeline_event["flow"]["byte_count"] == 51
    cases.append(("parser through full pipeline", 4, pipeline_event, "MATCH", None))
    cases.extend([
        ("missing event", 2, None, "NO_MATCH", None),
        ("missing transport", 2, {}, "NO_MATCH", None),
        ("malformed transport", 2, {"transport": []}, "NO_MATCH", None),
    ])
    matcher = PacketMatcher()
    counts = {"MATCH": 0, "NO_MATCH": 0}
    for name, suffix, normalized, expected, reason in cases:
        sid = 101200 + suffix
        saved = deepcopy(normalized)
        assert json.loads(json.dumps(normalized)) == normalized
        status = matcher.match(rules[sid], normalized)
        assert status == expected, (name, sid, status, expected)
        diagnostic = matcher.evaluate(rules[sid], normalized)
        assert isinstance(diagnostic, MatchResult) and diagnostic.rule is rules[sid]
        assert diagnostic.status == expected, (name, diagnostic)
        assert isinstance(diagnostic.reason, str) and diagnostic.reason
        if reason:
            assert reason in diagnostic.reason, (name, diagnostic.reason)
        assert normalized == saved, name
        counts[status] += 1
        print(f"PASS {name}: sid={sid}, result={status}")
    assert snapshot == {sid: asdict(rule) for sid, rule in rules.items()}
    assert INPUT.read_bytes() == original
    print(f"Cases: {len(cases)}; exact status assertions: {2 * len(cases)}; MATCH: {counts['MATCH']}; NO_MATCH: {counts['NO_MATCH']}")
    print("PASS real TCP/UDP parser bytes, exact flags, strict dsize comparisons/open range, diagnostics and pipeline compatibility")
    print("Scope: packet options only; Content/Evaluation Engine integration not implemented")
    print("T12 PASS")


if __name__ == "__main__":
    main()
