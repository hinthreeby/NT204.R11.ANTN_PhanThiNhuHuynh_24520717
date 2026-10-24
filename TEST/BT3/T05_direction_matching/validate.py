"""Verify header direction matching for official testcase T05."""

from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import json
import sys


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parents[2]))

from core_engine.header_matcher import HeaderMatcher
from core_engine.models import InternalRule, RuleHeader
from core_engine.rule_loader import RuleLoader
from core_engine.rule_parser import RuleParserValidator


INPUT = TEST_DIR / "sample.rules"
IP_A, PORT_A = "192.168.1.10", 50000
IP_B, PORT_B = "10.0.0.20", 80
EXPECTED_RULES = {
    500001: (2, ("alert", "tcp", IP_A, "50000", "->", IP_B, "80"), "T05 exact directional"),
    500002: (3, ("alert", "tcp", IP_A, "50000", "<>", IP_B, "80"), "T05 exact bidirectional"),
    500003: (4, ("alert", "tcp", "192.168.1.0/24", "49000:51000", "->", "10.0.0.0/24", "80:90"), "T05 CIDR directional"),
    500004: (5, ("alert", "tcp", "192.168.1.0/24", "49000:51000", "<>", "10.0.0.0/24", "80:90"), "T05 CIDR bidirectional"),
}


def make_event(
    src_ip: str = IP_A,
    src_port: int = PORT_A,
    dst_ip: str = IP_B,
    dst_port: int = PORT_B,
    protocol: str = "TCP",
) -> dict:
    """Build a fixture using the existing normalized event schema."""

    event = {
        "packet_id": 1,
        "timestamp": 1790000600.0,
        "network": {"protocol": "IPv4", "src_ip": src_ip, "dst_ip": dst_ip},
        "transport": {
            "protocol": protocol, "src_port": src_port, "dst_port": dst_port,
            "payload_length": 0, "payload_hex": "",
        },
        "application": {"protocol": "UNKNOWN"},
        "errors": [],
    }
    if protocol == "TCP":
        event["transport"]["flags"] = ["ACK"]
    return event


def missing_field(section: str, name: str) -> dict:
    """Remove one required endpoint field from a fixture."""

    event = make_event()
    del event[section][name]
    return event


def main() -> None:
    """Run positive and negative direction assertions."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")

    original = INPUT.read_bytes()
    loader = RuleLoader()
    parser = RuleParserValidator()
    matcher = HeaderMatcher()
    candidates = loader.load([INPUT])
    assert len(candidates) == 4 and not loader.issues
    rules = {}
    for candidate in candidates:
        result = parser.parse(candidate)
        assert result.status == "valid", (result.status, result.reason)
        assert result.source is candidate
        assert candidate.source == str(INPUT)
        rule = result.rule
        assert isinstance(rule, InternalRule) and isinstance(rule.header, RuleHeader)
        assert rule.sid in EXPECTED_RULES and rule.sid not in rules
        line, expected_header, msg = EXPECTED_RULES[rule.sid]
        assert candidate.line_number == line
        assert tuple(asdict(rule.header).values()) == expected_header
        assert rule.rev == 1 and rule.msg == msg
        rules[rule.sid] = rule
    assert set(rules) == set(EXPECTED_RULES)

    reverse = make_event(IP_B, PORT_B, IP_A, PORT_A)
    ip_only_reverse = make_event(IP_B, PORT_A, IP_A, PORT_B)
    port_only_reverse = make_event(IP_A, PORT_B, IP_B, PORT_A)
    cases = (
        ("exact forward A to B", 500001, make_event(), "MATCH"),
        ("exact reverse B to A", 500001, reverse, "NO_MATCH"),
        ("bidirectional forward", 500002, make_event(), "MATCH"),
        ("bidirectional reverse", 500002, reverse, "MATCH"),
        ("wrong source port", 500002, make_event(src_port=50001), "NO_MATCH"),
        ("wrong destination port", 500002, make_event(dst_port=81), "NO_MATCH"),
        ("wrong source IP", 500002, make_event(src_ip="192.168.1.11"), "NO_MATCH"),
        ("wrong destination IP", 500002, make_event(dst_ip="10.0.0.21"), "NO_MATCH"),
        ("exact IP-only reversal", 500002, ip_only_reverse, "NO_MATCH"),
        ("exact port-only reversal", 500002, port_only_reverse, "NO_MATCH"),
        ("UDP against TCP rule", 500002, make_event(protocol="UDP"), "NO_MATCH"),
        ("CIDR forward", 500003, make_event(), "MATCH"),
        ("CIDR directional reverse", 500003, reverse, "NO_MATCH"),
        ("source outside CIDR", 500003, make_event(src_ip="192.168.2.10"), "NO_MATCH"),
        ("destination outside CIDR", 500003, make_event(dst_ip="10.0.1.20"), "NO_MATCH"),
        ("source below range", 500003, make_event(src_port=48999), "NO_MATCH"),
        ("destination above range", 500003, make_event(dst_port=91), "NO_MATCH"),
        ("both lower range boundaries", 500003, make_event(src_port=49000, dst_port=80), "MATCH"),
        ("both upper range boundaries", 500003, make_event(src_port=51000, dst_port=90), "MATCH"),
        ("CIDR bidirectional forward", 500004, make_event(), "MATCH"),
        ("CIDR bidirectional reverse", 500004, reverse, "MATCH"),
        ("CIDR reverse upper boundaries", 500004, make_event(IP_B, 90, IP_A, 51000), "MATCH"),
        ("CIDR IP-only reversal", 500004, ip_only_reverse, "NO_MATCH"),
        ("CIDR port-only reversal", 500004, port_only_reverse, "NO_MATCH"),
        ("missing source IP", 500002, missing_field("network", "src_ip"), "NO_MATCH"),
        ("missing destination IP", 500002, missing_field("network", "dst_ip"), "NO_MATCH"),
        ("missing source port", 500002, missing_field("transport", "src_port"), "NO_MATCH"),
        ("missing destination port", 500002, missing_field("transport", "dst_port"), "NO_MATCH"),
        ("malformed IPv4", 500002, make_event(src_ip="999.0.0.1"), "NO_MATCH"),
        ("wrong port type", 500002, make_event(src_port="50000"), "NO_MATCH"),
    )
    counts = {"MATCH": 0, "NO_MATCH": 0}
    used_rules = set()
    for name, sid, event, expected in cases:
        rule = rules[sid]
        saved_event = deepcopy(event)
        saved_header = asdict(rule.header)
        assert json.loads(json.dumps(event)) == event
        actual = matcher.match(rule.header, event)
        assert actual == expected, (name, sid, expected, actual)
        assert event == saved_event and asdict(rule.header) == saved_header, name
        counts[actual] += 1
        used_rules.add(sid)
        print(f"PASS {name}: sid={sid}, direction={rule.header.direction}, result={actual}")

    assert len(cases) == 30
    assert counts == {"MATCH": 9, "NO_MATCH": 21}
    assert used_rules == set(EXPECTED_RULES)
    assert INPUT.read_bytes() == original
    print("Validated rules: 4; match assertions: 30; MATCH: 9; NO_MATCH: 21")
    print("T05 PASS")


if __name__ == "__main__":
    main()
