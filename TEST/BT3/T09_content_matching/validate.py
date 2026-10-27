"""Verify raw content conditions and local ASCII nocase for T09."""

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
PATTERNS = {
    100901: [(b"admin", False)],
    100902: [(b"admin", True)],
    100903: [(b"GET", False)],
    100904: [(b"\x00\xff", False)],
    100905: [(b"admin", True), (b"GET", False)],
    100906: [(b"aa", False)],
    100907: [(b"GET /admin", False)],
    100908: [(b'a|b;"c', False)],
}


def event(payload: bytes) -> dict:
    """Build a normalized TCP event containing the exact raw bytes."""

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
    """Compare matcher status and byte occurrences with fixed expectations."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")

    original = INPUT.read_bytes()
    loader = RuleLoader()
    results = [RuleParserValidator().parse(source) for source in loader.load([INPUT])]
    assert len(results) == 8 and not loader.issues
    assert all(result.status == "valid" for result in results)
    rules = {result.rule.sid: result.rule for result in results}
    assert set(rules) == set(PATTERNS)
    for sid, rule in rules.items():
        compiled = compile_content_patterns(rule)
        assert [(pattern.pattern, pattern.nocase) for pattern in compiled] == PATTERNS[sid]
        assert [pattern.content_index for pattern in compiled] == list(range(len(compiled)))
        assert all(rule.options[pattern.option_index].name == "content" for pattern in compiled)
    assert [pattern.option_index for pattern in compile_content_patterns(rules[100905])] == [1, 3]
    snapshot = {sid: asdict(rule) for sid, rule in rules.items()}
    cases = [
        ("sensitive lowercase", 1, b"admin", "MATCH", [(1, 0, 5)]),
        ("sensitive uppercase", 1, b"ADMIN", "NO_MATCH", []),
        ("sensitive title case", 1, b"Admin", "NO_MATCH", []),
        ("GET exact", 3, b"GET /admin", "MATCH", [(1, 0, 3)]),
        ("GET lowercase rejected", 3, b"get /admin", "NO_MATCH", []),
        ("nocase lowercase", 2, b"admin", "MATCH", [(1, 0, 5)]),
        ("nocase uppercase", 2, b"ADMIN", "MATCH", [(1, 0, 5)]),
        ("nocase mixed case", 2, b"AdMiN", "MATCH", [(1, 0, 5)]),
        ("absent sensitive", 1, b"ordinary payload", "NO_MATCH", []),
        ("absent nocase", 2, b"ordinary payload", "NO_MATCH", []),
        ("pattern in middle", 1, b"GET /admin HTTP", "MATCH", [(1, 5, 10)]),
        ("pattern at end", 1, b"xxadmin", "MATCH", [(1, 2, 7)]),
        ("multiple both match", 5, b"GET /admin", "MATCH", [(1, 5, 10), (3, 0, 3)]),
        ("multiple nocase scoped", 5, b"GET /ADMIN", "MATCH", [(1, 5, 10), (3, 0, 3)]),
        ("multiple only first matches", 5, b"get /ADMIN", "NO_MATCH", [(1, 5, 10)]),
        ("multiple only second matches", 5, b"GET /users", "NO_MATCH", []),
        ("multiple no occurrence ordering required", 5, b"GET ADMIN", "MATCH", [(1, 4, 9), (3, 0, 3)]),
        ("binary exact bytes", 4, b"\x01\x00\xff\x02", "MATCH", [(1, 1, 3)]),
        ("binary absent reversed bytes", 4, b"\xff\x00", "NO_MATCH", []),
        ("binary repeated", 4, b"\x00\xff\x00\xff", "MATCH", [(1, 0, 2), (1, 2, 4)]),
        ("mixed ASCII and hex", 7, b"GET /admin", "MATCH", [(1, 0, 10)]),
        ("escaped pipe quote and semicolon", 8, b'xxa|b;"cy', "MATCH", [(1, 2, 8)]),
        ("all overlapping occurrences", 6, b"aaaa", "MATCH", [(1, 0, 2), (1, 1, 3), (1, 2, 4)]),
        ("all nocase occurrences", 2, b"adminADMIN", "MATCH", [(1, 0, 5), (1, 5, 10)]),
        ("UTF-8 prefix preserves byte offsets", 2, b"\xc3\xa9ADMIN", "MATCH", [(1, 2, 7)]),
        ("empty payload", 1, b"", "NO_MATCH", []),
        ("raw payload is not URL decoded", 1, b"%61dmin", "NO_MATCH", []),
    ]
    prepared = [(name, suffix, event(payload), status, offsets) for name, suffix, payload, status, offsets in cases]
    missing = event(b"admin")
    del missing["transport"]["payload_hex"]
    prepared.append(("missing payload hex", 1, missing, "NO_MATCH", []))
    for value in (None, 123, "not-hex", "f"):
        malformed = event(b"admin")
        malformed["transport"]["payload_hex"] = value
        prepared.append((f"invalid payload hex {value!r}", 1, malformed, "NO_MATCH", []))
    inconsistent = event(b"admin")
    inconsistent["transport"]["payload_length"] = 4
    prepared.append(("conflicting payload length", 1, inconsistent, "NO_MATCH", []))
    decoded = event(b"%61dmin")
    decoded["application"]["decoded_body"] = "admin"
    prepared.append(("decoded body cannot replace raw bytes", 1, decoded, "NO_MATCH", []))
    matcher = ContentMatcher()
    counts = {"MATCH": 0, "NO_MATCH": 0}
    occurrences = 0
    for name, suffix, normalized, expected, offsets in prepared:
        sid = 100900 + suffix
        saved = deepcopy(normalized)
        assert json.loads(json.dumps(normalized)) == normalized
        status = matcher.match(rules[sid], normalized)
        assert status == expected, (name, sid, status, expected)
        result = matcher.evaluate(rules[sid], normalized)
        assert isinstance(result, MatchResult) and result.rule is rules[sid]
        assert result.status == expected, (name, result)
        assert isinstance(result.reason, str) and result.reason
        actual = [(info.option_index, info.start, info.end) for info in result.information]
        assert actual == offsets, (name, actual, offsets)
        for info in result.information:
            payload = bytes.fromhex(normalized["transport"]["payload_hex"])
            assert info.field == "transport.payload_hex"
            assert rules[sid].options[info.option_index].name == "content"
            assert info.matched_hex == payload[info.start:info.end].hex()
            assert info.end > info.start >= 0
            occurrences += 1
        assert normalized == saved, name
        counts[status] += 1
        print(f"PASS {name}: sid={sid}, content={status}, offsets={actual}")
    assert len(prepared) == 34
    assert snapshot == {sid: asdict(rule) for sid, rule in rules.items()}
    assert INPUT.read_bytes() == original
    print(f"Cases: {len(prepared)}; exact status assertions: {2 * len(prepared)}; offset-list assertions: {len(prepared)}; occurrences checked: {occurrences}")
    print(f"Content conditions: MATCH {counts['MATCH']}; NO_MATCH {counts['NO_MATCH']}")
    print("Scope: content conditions only, not a complete Snort rule verdict; positional/Evaluation Engine integration not implemented")
    print("T09 PASS")


if __name__ == "__main__":
    main()
