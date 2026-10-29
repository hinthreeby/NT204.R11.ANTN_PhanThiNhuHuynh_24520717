"""Verify relative byte windows and complete content chains for T11."""

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


def event(payload: bytes) -> dict:
    """Build a normalized TCP fixture containing exact raw payload bytes."""

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
    """Assert manually specified verdicts and successful-chain spans."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")

    original = INPUT.read_bytes()
    loader, parser = RuleLoader(), RuleParserValidator()
    results = [parser.parse(source) for source in loader.load([INPUT])]
    assert len(results) == 21 and not loader.issues
    assert all(result.status == "valid" for result in results)
    rules = {result.rule.sid: result.rule for result in results}
    assert set(rules) == set(range(101101, 101122))
    compiled = {sid: compile_content_patterns(rule) for sid, rule in rules.items()}
    assert [(option.name, option.value) for option in compiled[101103][1].modifiers] == [("distance", "1"), ("within", "6")]
    assert [pattern.nocase for pattern in compiled[101110]] == [True, True]
    assert [pattern.pattern for pattern in compiled[101111]] == [b"\x00\xff", b"\x10\xfe"]
    snapshot = {sid: asdict(rule) for sid, rule in rules.items()}
    cases = [
        ("distance three exact", 1, b"ABCxxxDEF", "MATCH", [(1, 0, 3), (2, 6, 9)]),
        ("distance rejects content too early", 1, b"ABCxxDEF", "NO_MATCH", []),
        ("distance has no upper bound", 1, b"ABCxxxxDEF", "MATCH", [(1, 0, 3), (2, 7, 10)]),
        ("distance starts at previous end not start", 1, b"ABCDEF", "NO_MATCH", []),
        ("distance zero adjacent", 4, b"ABCDEF", "MATCH", [(1, 0, 3), (2, 3, 6)]),
        ("distance after nonzero first position", 1, b"XXXABCxxxDEF", "MATCH", [(1, 3, 6), (2, 9, 12)]),
        ("within six exact right boundary", 2, b"ABCxxxDEF", "MATCH", [(1, 0, 3), (2, 6, 9)]),
        ("within six exceeded by one byte", 2, b"ABCxxxxDEF", "NO_MATCH", []),
        ("within relative not absolute depth", 2, b"XXXXABCxxxDEF", "MATCH", [(1, 4, 7), (2, 10, 13)]),
        ("within exactly pattern length", 5, b"ABCDEF", "MATCH", [(1, 0, 3), (2, 3, 6)]),
        ("within shorter than pattern", 6, b"ABCDEF", "NO_MATCH", []),
        ("combined window inside", 3, b"ABCxxxDEF", "MATCH", [(1, 0, 3), (2, 6, 9)]),
        ("combined window right boundary", 3, b"ABCxxxxDEF", "MATCH", [(1, 0, 3), (2, 7, 10)]),
        ("combined window crossed by one byte", 3, b"ABCxxxxxDEF", "NO_MATCH", []),
        ("combined within starts after distance", 7, b"ABCxxxDEF", "MATCH", [(1, 0, 3), (2, 6, 9)]),
        ("distance true within false", 8, b"ABCxxxDEF", "NO_MATCH", []),
        ("within possible distance false", 9, b"ABCxxxDEF", "NO_MATCH", []),
        ("later first occurrence succeeds", 5, b"ABCxxxxABCDEF", "MATCH", [(1, 7, 10), (2, 10, 13)]),
        ("later second occurrence reaches third", 16, b"ABCDEFxxxDEFZ", "MATCH", [(1, 0, 3), (2, 9, 12), (4, 12, 13)]),
        ("incompatible branches cannot be joined", 17, b"ABxxxBC", "NO_MATCH", []),
        ("three contents need later branch", 18, b"ABABCD", "MATCH", [(1, 2, 3), (2, 3, 4), (4, 4, 6)]),
        ("two existing contents outside window", 5, b"ABCxxxDEF", "NO_MATCH", []),
        ("nocase relative", 10, b"ABCxxxDeF", "MATCH", [(1, 0, 3), (3, 6, 9)]),
        ("binary relative bytes", 11, b"\x00\xffx\x10\xfe", "MATCH", [(1, 0, 2), (2, 3, 5)]),
        ("negative distance overlaps previous match", 12, b"ABC", "MATCH", [(1, 0, 3), (2, 1, 3)]),
        ("negative start clips at buffer zero", 13, b"AB", "MATCH", [(1, 1, 2), (2, 0, 1)]),
        ("negative end is not a Python slice index", 14, b"AB", "NO_MATCH", []),
        ("negative distance without within reaches end", 20, b"AxxxZ", "MATCH", [(1, 0, 1), (2, 4, 5)]),
        ("unmodified contents have no implicit order", 15, b"ABCDEF", "MATCH", [(1, 3, 6), (2, 0, 3)]),
        ("absolute then relative windows", 19, b"AxxxxBC", "MATCH", [(1, 0, 1), (3, 5, 6), (6, 6, 7)]),
        ("independent content resets relative anchor", 21, b"BCxxxA", "MATCH", [(1, 5, 6), (2, 0, 1), (3, 1, 2)]),
        ("empty payload", 1, b"", "NO_MATCH", []),
        ("no cursor from previous event", 4, b"DEF", "NO_MATCH", []),
    ]
    prepared = [(name, suffix, event(payload), status, spans) for name, suffix, payload, status, spans in cases]
    missing = event(b"ABCxxxDEF")
    del missing["transport"]["payload_hex"]
    prepared.append(("missing payload", 1, missing, "NO_MATCH", []))
    for value in (None, 123, "not-hex", "f"):
        malformed = event(b"ABCxxxDEF")
        malformed["transport"]["payload_hex"] = value
        prepared.append((f"malformed payload {value!r}", 1, malformed, "NO_MATCH", []))
    conflict = event(b"ABCxxxDEF")
    conflict["transport"]["payload_length"] = 1
    prepared.append(("conflicting payload length", 1, conflict, "NO_MATCH", []))
    matcher = ContentMatcher()
    counts = {"MATCH": 0, "NO_MATCH": 0}
    occurrence_checks = relative_checks = 0
    for name, suffix, normalized, expected, spans in prepared:
        sid = 101100 + suffix
        saved = deepcopy(normalized)
        assert json.loads(json.dumps(normalized)) == normalized
        assert matcher.match(rules[sid], normalized) == expected, name
        result = matcher.evaluate(rules[sid], normalized)
        assert isinstance(result, MatchResult) and result.rule is rules[sid]
        assert result.status == expected, (name, result)
        assert isinstance(result.reason, str) and result.reason
        actual_spans = [(info.option_index, info.start, info.end) for info in result.information]
        assert actual_spans == spans, (name, actual_spans, spans)
        if expected == "NO_MATCH":
            assert not result.information, (name, "failed path leaked")
        previous_end = None
        for info, pattern in zip(result.information, compiled[sid]):
            payload = bytes.fromhex(normalized["transport"]["payload_hex"])
            assert info.option_index == pattern.option_index
            assert info.field == "transport.payload_hex"
            assert 0 <= info.start < info.end <= len(payload)
            assert info.matched_hex == payload[info.start:info.end].hex()
            matched = payload[info.start:info.end]
            assert (matched.lower() == pattern.pattern.lower()) if pattern.nocase else (matched == pattern.pattern)
            modifiers = {option.name: option.value for option in pattern.modifiers}
            if modifiers.keys() & {"distance", "within"}:
                assert previous_end is not None
                lower = previous_end + int(modifiers.get("distance", "0"))
                upper = lower + int(modifiers["within"]) if "within" in modifiers else len(payload)
                assert max(0, lower) <= info.start and info.end <= min(len(payload), upper)
                relative_checks += 1
            previous_end = info.end
            occurrence_checks += 1
        if result.status == "MATCH":
            assert len(result.information) == len(compiled[sid])
        assert normalized == saved, name
        counts[result.status] += 1
        print(f"PASS {name}: sid={sid}, content={result.status}, spans={actual_spans}")
    assert len(prepared) == 39
    assert snapshot == {sid: asdict(rule) for sid, rule in rules.items()}
    assert INPUT.read_bytes() == original
    print(f"Cases: {len(prepared)}; exact status assertions: {2 * len(prepared)}; span-list assertions: {len(prepared)}")
    print(f"Content conditions: MATCH {counts['MATCH']}; NO_MATCH {counts['NO_MATCH']}; occurrences checked: {occurrence_checks}; relative windows checked: {relative_checks}")
    print("PASS alternative first/second occurrences, incompatible branches, negative distance and three-content chains")
    print("Scope: content conditions only; no Evaluation Engine or Detection Event integration")
    print("T11 PASS")


if __name__ == "__main__":
    main()
