"""Verify header filtering before test-only content handoff for T07."""

from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import json
import sys


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parents[2]))

from core_engine.header_matcher import HeaderMatcher
from core_engine.rule_loader import RuleLoader
from core_engine.rule_parser import RuleParserValidator
from core_engine.rule_repository import RuleRepository


INPUT = TEST_DIR / "sample.rules"
PAYLOAD = b"GET /admin HTTP/1.1\r\nHost: example.test\r\n\r\n"


def event(protocol="TCP", src_ip="192.168.1.10", src_port=50000,
          dst_ip="192.168.1.100", dst_port=80) -> dict:
    """Build a normalized fixture with the original transport bytes."""

    return {
        "packet_id": 1, "timestamp": 1790000700.0,
        "network": {"protocol": "IPv4", "src_ip": src_ip, "dst_ip": dst_ip},
        "transport": {
            "protocol": protocol, "src_port": src_port, "dst_port": dst_port,
            "payload_hex": PAYLOAD.hex(), "payload_length": len(PAYLOAD),
            **({"flags": ["PSH", "ACK"]} if protocol == "TCP" else {}),
        },
        "application": {"protocol": "UNKNOWN"}, "errors": [],
    }


def missing(section: str, field: str) -> dict:
    """Remove a required endpoint field from an event."""

    normalized = event()
    del normalized[section][field]
    return normalized


class ContentHandoffSpy:
    """Record downstream handoffs without evaluating content."""

    def __init__(self) -> None:
        self.calls = []

    def __call__(self, rule, normalized) -> None:
        self.calls.append((rule.sid, normalized))


def main() -> None:
    """Check exact filtered SID sets and test-only handoff counts."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")

    original = INPUT.read_bytes()
    loader = RuleLoader()
    parser = RuleParserValidator()
    sources = loader.load([INPUT])
    results = [parser.parse(source) for source in sources]
    assert len(results) == 4 and not loader.issues
    assert all(result.status == "valid" for result in results)
    rules = {result.rule.sid: result.rule for result in results}
    assert set(rules) == {700001, 700002, 700003, 700004}
    assert all(
        [option.value for option in rule.options if option.name == "content"] == ['"admin"']
        for rule in rules.values()
    )
    snapshot = {sid: asdict(rule) for sid, rule in rules.items()}
    reverse = event(src_ip="192.168.1.100", src_port=80,
                    dst_ip="192.168.1.10", dst_port=50000)
    cases = (
        ("valid exact header", (700001,), event(), {700001}),
        ("protocol mismatch", (700001,), event("UDP"), set()),
        ("source IP mismatch", (700001,), event(src_ip="192.168.1.11"), set()),
        ("destination IP mismatch", (700001,), event(dst_ip="192.168.1.101"), set()),
        ("source port mismatch", (700001,), event(src_port=50001), set()),
        ("destination port 443 despite admin payload", (700001,), event(dst_port=443), set()),
        ("directional reverse", (700001,), reverse, set()),
        ("bidirectional forward", (700002,), event(), {700002}),
        ("bidirectional reverse", (700002,), reverse, {700002}),
        ("bidirectional IP-only reverse", (700002,), event(src_ip="192.168.1.100", dst_ip="192.168.1.10"), set()),
        ("bidirectional port-only reverse", (700002,), event(src_port=80, dst_port=50000), set()),
        ("CIDR forward", (700003,), event(), {700003}),
        ("source outside CIDR", (700003,), event(src_ip="192.168.2.10"), set()),
        ("destination outside CIDR", (700003,), event(dst_ip="192.168.2.100"), set()),
        ("source below range", (700003,), event(src_port=48999), set()),
        ("source above range", (700003,), event(src_port=51001), set()),
        ("destination below range", (700003,), event(dst_port=79), set()),
        ("destination above range", (700003,), event(dst_port=91), set()),
        ("lower range boundaries", (700003,), event(src_port=49000, dst_port=80), {700003}),
        ("upper range boundaries", (700003,), event(src_port=51000, dst_port=90), {700003}),
        ("missing source IP", (700001,), missing("network", "src_ip"), set()),
        ("missing destination IP", (700001,), missing("network", "dst_ip"), set()),
        ("missing source port", (700001,), missing("transport", "src_port"), set()),
        ("missing destination port", (700001,), missing("transport", "dst_port"), set()),
        ("malformed IP", (700001,), event(src_ip="999.0.0.1"), set()),
        ("invalid port type", (700001,), event(src_port="50000"), set()),
        ("valid UDP header", (700004,), event("UDP"), {700004}),
        ("mixed rule set forward", tuple(rules), event(), {700001, 700002, 700003}),
        ("mixed rule set reverse", tuple(rules), reverse, {700002}),
    )
    matcher = HeaderMatcher()
    total_handoffs = rejected = 0
    for name, selected, normalized, expected in cases:
        saved = deepcopy(normalized)
        assert bytes.fromhex(normalized["transport"]["payload_hex"]) == PAYLOAD
        assert b"admin" in PAYLOAD
        assert normalized["transport"]["payload_length"] == len(PAYLOAD)
        assert json.loads(json.dumps(normalized)) == normalized
        repository = RuleRepository()
        for sid in selected:
            repository.add(rules[sid])
        candidates = repository.candidates(normalized)
        filtered = repository.header_matches(normalized)
        actual = {rule.sid for rule in filtered}
        baseline = {
            sid for sid in selected if matcher.match(rules[sid].header, normalized) == "MATCH"
        }
        assert actual == expected, (name, actual, expected)
        assert actual == baseline, (name, actual, baseline)
        assert expected <= {rule.sid for rule in candidates}, name
        assert len(filtered) == len(actual), name
        assert len(candidates) == len({rule.sid for rule in candidates}), name

        # Observe only the test harness boundary after real header filtering.
        spy = ContentHandoffSpy()
        for rule in filtered:
            spy(rule, normalized)
        called = [sid for sid, _ in spy.calls]
        assert set(called) == expected and len(called) == len(expected), name
        assert all(passed_event is normalized for _, passed_event in spy.calls), name
        assert not (set(selected) - expected) & set(called), name
        if not expected:
            assert len(spy.calls) == 0, name
            rejected += 1
        total_handoffs += len(spy.calls)
        assert normalized == saved, name
        print(f"PASS {name}: filtered={sorted(actual)}; content handoffs={len(spy.calls)}")

    assert len(cases) == 29 and rejected == 20 and total_handoffs == 11
    assert snapshot == {sid: asdict(rule) for sid, rule in rules.items()}
    assert INPUT.read_bytes() == original
    print("Cases: 29; filtered SID-set assertions: 29; spy checks: 29; rejected cases: 20; handoffs: 11")
    print("Scope: Header Filtering and test-only handoff; Content Matcher/Evaluation Engine end-to-end NOT TESTED")
    print("T07 PASS")


if __name__ == "__main__":
    main()
