"""Verify absolute content search windows for official testcase T10."""

from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import json
import sys


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parents[2]))

from core_engine.content_matcher import ContentMatcher
from core_engine.content_pattern import compile_content_patterns
from core_engine.models import MatchResult
from core_engine.rule_loader import RuleLoader
from core_engine.rule_parser import RuleParserValidator


INPUT = TEST_DIR / "sample.rules"
BASE = b"XXABCYYABC"
WINDOWS = {
    1: (2, None), 2: (0, 5), 3: (5, 5), 4: (5, 4), 5: (2, 3),
    6: (0, 2), 7: (0, None), 8: (10, None), 9: (11, None),
    10: (0, 100), 11: (5, 5), 12: (2, 2), 13: (0, None),
    14: (7, 3), 15: (1, 3), 16: (7, 100),
}


def event(payload: bytes) -> dict:
    """Build a normalized TCP fixture with the original payload bytes."""

    return {
        "packet_id": 1, "timestamp": 1000.0,
        "network": {"protocol": "IPv4", "src_ip": "192.168.1.10", "dst_ip": "192.168.1.20", "total_length": 40 + len(payload)},
        "transport": {
            "protocol": "TCP", "src_port": 50000, "dst_port": 80, "flags": ["ACK"],
            "payload_hex": payload.hex(), "payload_length": len(payload),
        },
        "application": {"protocol": "UNKNOWN"}, "errors": [],
    }


def main() -> None:
    """Check fixed verdicts, exact spans and full-pattern containment."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")

    original = INPUT.read_bytes()
    loader = RuleLoader()
    results = [RuleParserValidator().parse(source) for source in loader.load([INPUT])]
    assert len(results) == 16 and not loader.issues
    assert all(result.status == "valid" for result in results)
    rules = {result.rule.sid: result.rule for result in results}
    assert set(rules) == set(range(101001, 101017))
    for sid, rule in rules.items():
        pattern = compile_content_patterns(rule)[0]
        values = {option.name: option.value for option in pattern.modifiers}
        assert (int(values.get("offset", "0")), int(values["depth"]) if "depth" in values else None) == WINDOWS[sid - 101000]
        assert pattern.nocase is (sid == 101011)
        assert pattern.pattern == (b"\x00\xff" if sid == 101012 else b"aa" if sid == 101015 else b"ABC")
    assert len(compile_content_patterns(rules[101014])) == 2
    assert not compile_content_patterns(rules[101014])[1].modifiers
    snapshot = {sid: asdict(rule) for sid, rule in rules.items()}
    cases = [
        ("offset starts at exact occurrence", 1, BASE, "MATCH", [(1, 2, 5), (1, 7, 10)]),
        ("occurrence only before offset", 1, b"ABCYY", "NO_MATCH", []),
        ("occurrence after offset", 1, b"XXXXABC", "MATCH", [(1, 4, 7)]),
        ("depth enough through right boundary", 2, BASE, "MATCH", [(1, 2, 5)]),
        ("depth crossed by one byte", 2, b"XXXABC", "NO_MATCH", []),
        ("offset five depth five selects second", 3, BASE, "MATCH", [(1, 7, 10)]),
        ("offset five depth four rejects second", 4, BASE, "NO_MATCH", []),
        ("exact left and right window boundaries", 5, BASE, "MATCH", [(1, 2, 5)]),
        ("depth shorter than pattern", 6, b"ABC", "NO_MATCH", []),
        ("offset zero starts at first byte", 7, b"ABC", "MATCH", [(1, 0, 3)]),
        ("offset equal to payload length", 8, BASE, "NO_MATCH", []),
        ("offset exceeds payload length", 9, BASE, "NO_MATCH", []),
        ("depth clipped at buffer end", 10, BASE, "MATCH", [(1, 2, 5), (1, 7, 10)]),
        ("nocase preserves original offsets", 11, b"XXaBcYYaBC", "MATCH", [(1, 7, 10)]),
        ("binary exact window", 12, b"xx\x00\xffy\x00\xff", "MATCH", [(1, 2, 4)]),
        ("binary crosses right boundary", 12, b"xxx\x00\xff", "NO_MATCH", []),
        ("unmodified content retains all occurrences", 13, BASE, "MATCH", [(1, 2, 5), (1, 7, 10)]),
        ("window does not affect second content", 14, BASE, "MATCH", [(1, 7, 10), (4, 0, 2)]),
        ("overlapping occurrences inside window", 15, b"aaaa", "MATCH", [(1, 1, 3), (1, 2, 4)]),
        ("offset and large depth clip safely", 16, BASE, "MATCH", [(1, 7, 10)]),
        ("UTF-8 prefix uses byte index two", 5, b"\xc3\xa9ABC", "MATCH", [(1, 2, 5)]),
        ("empty payload with window", 5, b"", "NO_MATCH", []),
        ("absent content inside window", 5, b"XXZZZYYABC", "NO_MATCH", []),
    ]
    prepared = [(name, suffix, event(payload), status, spans) for name, suffix, payload, status, spans in cases]
    missing = event(BASE)
    del missing["transport"]["payload_hex"]
    prepared.append(("missing raw payload", 5, missing, "NO_MATCH", []))
    for value in (None, 123, "not-hex", "f"):
        malformed = event(BASE)
        malformed["transport"]["payload_hex"] = value
        prepared.append((f"malformed raw payload {value!r}", 5, malformed, "NO_MATCH", []))
    inconsistent = event(BASE)
    inconsistent["transport"]["payload_length"] = 1
    prepared.append(("conflicting payload length", 5, inconsistent, "NO_MATCH", []))
    matcher = ContentMatcher()
    counts = {"MATCH": 0, "NO_MATCH": 0}
    occurrences = 0
    for name, suffix, normalized, expected, spans in prepared:
        sid = 101000 + suffix
        saved = deepcopy(normalized)
        assert json.loads(json.dumps(normalized)) == normalized
        actual = matcher.match(rules[sid], normalized)
        assert actual == expected, (name, actual, expected)
        result = matcher.evaluate(rules[sid], normalized)
        assert isinstance(result, MatchResult) and result.rule is rules[sid]
        assert result.status == expected, (name, result)
        assert isinstance(result.reason, str) and result.reason
        positions = [(info.option_index, info.start, info.end) for info in result.information]
        assert positions == spans, (name, positions, spans)
        for info in result.information:
            payload = bytes.fromhex(normalized["transport"]["payload_hex"])
            offset, depth = (0, None) if suffix == 14 and info.option_index == 4 else WINDOWS[suffix]
            limit = min(len(payload), offset + depth) if depth is not None else len(payload)
            assert offset <= info.start < info.end <= limit, (name, info)
            assert info.field == "transport.payload_hex"
            assert info.matched_hex == payload[info.start:info.end].hex()
            assert rules[sid].options[info.option_index].name == "content"
            occurrences += 1
        assert normalized == saved, name
        counts[actual] += 1
        print(f"PASS {name}: sid={sid}, content={actual}, spans={positions}")
    assert len(prepared) == 29
    assert snapshot == {sid: asdict(rule) for sid, rule in rules.items()}
    assert INPUT.read_bytes() == original
    print(f"Cases: {len(prepared)}; exact status assertions: {2 * len(prepared)}; span-list assertions: {len(prepared)}; contained occurrences: {occurrences}")
    print(f"Content conditions: MATCH {counts['MATCH']}; NO_MATCH {counts['NO_MATCH']}")
    print("Scope: absolute content windows only; no relative matching or complete Snort rule evaluation")
    print("T10 PASS")


if __name__ == "__main__":
    main()
