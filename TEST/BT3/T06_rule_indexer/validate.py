"""Verify indexed candidates and header filtering for official testcase T06."""

from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import json
import sys


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parents[2]))

from core_engine.header_matcher import HeaderMatcher
from core_engine.rule_loader import RuleLoader, RuleLoaderConfig
from core_engine.rule_parser import RuleParserValidator
from core_engine.rule_repository import RuleRepository


INPUT = TEST_DIR / "sample.rules"
ACTIVE = set(range(600001, 600009))


def event(protocol="TCP", src_ip="192.168.1.10", src_port=50000,
          dst_ip="10.0.0.20", dst_port=80) -> dict:
    """Build an event using the existing normalized schema."""

    return {
        "packet_id": 1, "timestamp": 1790000600.0,
        "network": {"protocol": "IPv4", "src_ip": src_ip, "dst_ip": dst_ip},
        "transport": {
            "protocol": protocol, "src_port": src_port, "dst_port": dst_port,
            "payload_hex": "", "payload_length": 0,
            **({"flags": ["ACK"]} if protocol == "TCP" else {}),
        },
        "application": {"protocol": "UNKNOWN"}, "errors": [],
    }


def sids(*numbers) -> set[int]:
    """Expand the fixture SID suffixes."""

    return {600000 + number for number in numbers}


def main() -> None:
    """Check fixed expected sets and a full-scan baseline."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")

    original = INPUT.read_bytes()
    parser = RuleParserValidator()
    loader = RuleLoader(RuleLoaderConfig(rule_enabled={600009: False}))
    sources = loader.load([INPUT])
    results = [parser.parse(source) for source in sources]
    assert len(results) == 11 and not loader.issues
    assert [result.status for result in results] == ["valid"] * 9 + ["invalid", "unsupported"]
    assert all(result.reason for result in results)
    assert results[9].rule is results[10].rule is None
    assert results[8].rule.sid == 600009 and not loader.is_rule_enabled(results[8].rule)

    repository = RuleRepository()
    repository.rebuild([INPUT], loader, parser)
    assert {rule.sid for rule in repository.active_rules} == ACTIVE
    assert len(repository.active_rules) == 8
    snapshot = tuple(asdict(rule) for rule in repository.active_rules)
    reordered = RuleRepository(loader)
    for result in reversed(results):
        reordered.add_validated(result)

    missing_ip = event()
    del missing_ip["network"]["src_ip"]
    missing_port = event()
    del missing_port["transport"]["dst_port"]
    cases = (
        ("TCP exact and any", event(), sids(1, 2, 3, 4), sids(1, 2, 3, 4)),
        ("TCP wrong exact IP", event(src_ip="192.168.1.11"), sids(1, 2, 3, 4), sids(2, 3, 4)),
        ("TCP outside source CIDR", event(src_ip="192.168.2.10"), sids(1, 2, 3, 4), sids(2, 4)),
        ("TCP outside destination CIDR", event(dst_ip="10.0.1.20", dst_port=85), sids(3, 4), sids(4)),
        ("TCP lower range boundaries", event(src_port=49000), sids(1, 2, 3, 4), sids(2, 3, 4)),
        ("TCP upper range boundaries", event(src_port=51000, dst_port=90), sids(3, 4), sids(3, 4)),
        ("TCP source below range", event(src_port=48999), sids(1, 2, 3, 4), sids(2, 4)),
        ("TCP destination above range", event(dst_port=91), sids(3, 4), sids(4)),
        ("TCP reverse range", event(src_ip="10.0.0.20", src_port=90, dst_ip="192.168.1.10", dst_port=51000), sids(3, 4), sids(3, 4)),
        ("TCP bidirectional single forward", event(dst_port=443), sids(3, 4, 8), sids(4, 8)),
        ("TCP bidirectional single reverse", event(src_ip="10.0.0.20", src_port=443, dst_ip="192.168.1.10", dst_port=50000), sids(3, 4, 8), sids(4, 8)),
        ("TCP IP-only reversal", event(src_ip="10.0.0.20", dst_ip="192.168.1.10"), sids(1, 2, 3, 4), sids(2, 4)),
        ("TCP port-only reversal", event(src_port=80, dst_port=50000), sids(3, 4), sids(4)),
        ("TCP any port boundaries", event(src_port=0, dst_port=65535), sids(3, 4), sids(4)),
        ("UDP exact and any", event("UDP", src_port=53000, dst_port=53), sids(5, 6, 7), sids(5, 6)),
        ("UDP wrong exact IP", event("UDP", src_ip="203.0.113.1", src_port=53000, dst_port=53), sids(5, 6, 7), sids(6)),
        ("UDP lower range boundary", event("UDP", src_port=0, dst_port=100), sids(7), sids(7)),
        ("UDP upper range boundary", event("UDP", src_port=65535, dst_port=200), sids(7), sids(7)),
        ("UDP below range", event("UDP", dst_port=99), sids(7), set()),
        ("UDP above range", event("UDP", dst_port=201), sids(7), set()),
        ("UDP outside CIDR", event("UDP", src_ip="192.168.2.10", dst_port=150), sids(7), set()),
        ("unknown protocol", event("ICMP"), set(), set()),
        ("missing IP", missing_ip, sids(1, 2, 3, 4), set()),
        ("invalid IP", event(src_ip="999.0.0.1"), sids(1, 2, 3, 4), set()),
        ("missing port", missing_port, set(), set()),
        ("invalid port type", event(src_port="50000"), set(), set()),
    )
    matcher = HeaderMatcher()
    for name, normalized, expected_candidates, expected_headers in cases:
        saved = deepcopy(normalized)
        assert json.loads(json.dumps(normalized)) == normalized
        candidates = repository.candidates(normalized)
        headers = repository.header_matches(normalized)
        actual_candidates = {rule.sid for rule in candidates}
        actual_headers = {rule.sid for rule in headers}
        baseline = {
            rule.sid for rule in repository.active_rules
            if matcher.match(rule.header, normalized) == "MATCH"
        }
        assert actual_candidates == expected_candidates, (name, actual_candidates, expected_candidates)
        assert actual_headers == expected_headers, (name, actual_headers, expected_headers)
        assert baseline <= actual_candidates, (name, "false negative", baseline - actual_candidates)
        assert actual_headers == baseline, (name, actual_headers, baseline)
        assert len(candidates) == len(actual_candidates) and len(headers) == len(actual_headers), name
        assert actual_candidates <= ACTIVE and actual_headers <= ACTIVE, name
        assert all(repository.get(rule.sid) is rule for rule in candidates), name
        assert {rule.sid for rule in reordered.candidates(normalized)} == expected_candidates, name
        assert {rule.sid for rule in reordered.header_matches(normalized)} == expected_headers, name
        assert normalized == saved, name
        print(f"PASS {name}: candidates={sorted(actual_candidates)}; headers={sorted(actual_headers)}")

    empty = RuleRepository()
    assert empty.candidates(event()) == empty.header_matches(event()) == ()
    repository.rebuild([], loader, parser)
    assert repository.active_rules == ()
    assert repository.candidates(event()) == repository.header_matches(event()) == ()
    assert tuple(asdict(rule) for rule in reordered.active_rules)[::-1] == snapshot
    assert INPUT.read_bytes() == original
    assert len(cases) == 26
    print("Event cases: 26; SID-set assertions: 52; full-scan baseline comparisons: 26")
    print("PASS: empty/rebuilt repository; disabled/invalid/unsupported excluded; no duplicates or false negatives")
    print("T06 PASS")


if __name__ == "__main__":
    main()
