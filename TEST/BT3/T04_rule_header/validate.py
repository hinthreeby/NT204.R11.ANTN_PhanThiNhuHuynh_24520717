"""Verify Internal Rule Object fields for official testcase T04."""

from pathlib import Path
import json
import sys


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parents[2]))

from core_engine.models import InternalRule, RuleHeader, RuleValidationResult
from core_engine.rule_loader import RuleLoader
from core_engine.rule_parser import RuleParserValidator


INPUT = TEST_DIR / "sample.rules"
HEADER_FIELDS = (
    "action", "protocol", "src_ip", "src_port", "direction", "dst_ip", "dst_port",
)
FIELDS = HEADER_FIELDS + ("sid", "rev", "msg")
VALID = {
    2: ("alert", "tcp", "192.0.2.10", "50000", "->", "198.51.100.20", "80",
        400001, 1, "T04 TCP exact IPv4"),
    3: ("alert", "tcp", "any", "any", "->", "198.51.100.20", "443",
        400002, 2, "T04 TCP any source"),
    4: ("alert", "tcp", "192.0.2.10", "12345", "->", "any", "any",
        400003, 3, "T04 TCP any destination"),
    5: ("alert", "tcp", "192.0.2.129/24", "1000:2000", "->", "198.51.100.25", "25",
        400004, 1, "T04 TCP source CIDR"),
    6: ("alert", "tcp", "192.0.2.10", "443", "<>", "198.51.100.129/24", "1024:65535",
        400005, 2, "T04 TCP destination CIDR"),
    7: ("alert", "tcp", "0.0.0.0/0", "0:65535", "<>", "203.0.113.7/32", "80:80",
        400006, 3, "T04 TCP CIDR and range boundaries"),
    8: ("alert", "tcp", "any", "0", "->", "any", "65535",
        400007, 1, "T04 TCP single port boundaries"),
    9: ("alert", "udp", "192.0.2.53", "53", "<>", "198.51.100.0/24", "50000:60000",
        400008, 4, "T04 UDP regression"),
}
INVALID = {
    10: "Invalid IPv4/CIDR: 999.0.0.1",
    11: "Invalid IPv4/CIDR: 198.51.100.0/33",
    12: "Port must be in 0..65535",
    13: "Port range is reversed",
    14: "Invalid header direction: =>; expected -> or <>",
}


def main() -> None:
    """Check exact header fields, identification and invalid controls."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")

    original = INPUT.read_bytes()
    lines = original.decode("utf-8").splitlines()
    loader = RuleLoader()
    parser = RuleParserValidator()
    candidates = loader.load([INPUT])
    assert len(lines) == 14
    assert len(candidates) == len(VALID) + len(INVALID) == 13
    assert [candidate.line_number for candidate in candidates] == sorted(VALID.keys() | INVALID.keys())
    assert not loader.issues

    accepted = []
    field_assertions = 0
    for candidate in candidates:
        line = candidate.line_number
        assert candidate.source == str(INPUT)
        assert candidate.text == lines[line - 1]
        result = parser.parse(candidate)
        assert isinstance(result, RuleValidationResult)
        assert result.source is candidate
        assert isinstance(result.reason, str) and result.reason.strip()
        if line in VALID:
            assert result.status == "valid", (line, result.status, result.reason)
            rule = result.rule
            assert isinstance(rule, InternalRule)
            assert isinstance(rule.header, RuleHeader)
            assert len(VALID[line]) == len(FIELDS) == 10
            actual = {}
            for name, expected in zip(FIELDS, VALID[line]):
                value = getattr(rule.header if name in HEADER_FIELDS else rule, name)
                assert type(value) is type(expected) and value == expected, (line, name, value, expected)
                actual[name] = value
                field_assertions += 1
            accepted.append(rule)
            print(f"PASS line {line}: valid; " + json.dumps(actual))
        else:
            assert result.status == "invalid", (line, result.status, result.reason)
            assert result.rule is None
            assert result.reason == INVALID[line], (line, result.reason)
            print(f"PASS line {line}: invalid; {result.reason}")

    assert [rule.sid for rule in accepted] == list(range(400001, 400009))
    assert sum(rule.header.protocol == "tcp" for rule in accepted) == 7
    assert sum(rule.header.protocol == "udp" for rule in accepted) == 1
    assert field_assertions == 80
    assert INPUT.read_bytes() == original
    print("Field value/type assertions: 80 (10 per valid rule)")
    print("Cases: 13; valid TCP: 7; valid UDP: 1; invalid: 5")
    print("T04 PASS")


if __name__ == "__main__":
    main()
