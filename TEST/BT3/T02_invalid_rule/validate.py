"""Verify invalid rule handling for official testcase T02."""

from pathlib import Path
import sys


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parents[2]))

from core_engine.models import InternalRule, RuleValidationResult
from core_engine.rule_loader import RuleLoader
from core_engine.rule_parser import RuleParserValidator


INPUT = TEST_DIR / "invalid.rules"
EXPECTED = (
    (2, "valid before errors", "valid", None),
    (3, "missing header component", "invalid",
     "Header requires action protocol src_ip src_port direction dst_ip dst_port"),
    (4, "missing options parentheses", "invalid", "Missing parenthesized rule options"),
    (5, "malformed protocol token", "invalid", "Action and protocol must be identifiers"),
    (6, "port outside range", "invalid", "Port must be in 0..65535"),
    (7, "malformed IPv4 address", "invalid", "Invalid IPv4/CIDR: 999.0.0.1"),
    (8, "non-integer SID", "invalid", "sid requires a decimal integer"),
    (9, "invalid revision", "invalid", "rev must be >= 1"),
    (10, "unclosed quoted content", "invalid",
     "Unclosed quote/escape or missing closing parenthesis"),
    (11, "missing closing parenthesis", "invalid",
     "Unclosed quote/escape or missing closing parenthesis"),
    (12, "unsupported protocol control", "unsupported", "Unsupported protocol: icmp"),
    (13, "unsupported keyword control", "unsupported", "Unsupported options: pcre"),
    (14, "valid after errors", "valid", None),
)


def main() -> None:
    """Check classifications, diagnostics and continued rule processing."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")

    original = INPUT.read_bytes()
    lines = original.decode("utf-8").splitlines()
    loader = RuleLoader()
    parser = RuleParserValidator()
    candidates = loader.load([INPUT])
    assert len(lines) == 14
    assert len(candidates) == len(EXPECTED) == 13
    assert [candidate.line_number for candidate in candidates] == list(range(2, 15))
    assert not loader.issues

    results = []
    accepted = []
    for candidate, (line, name, status, reason) in zip(candidates, EXPECTED):
        assert candidate.source == str(INPUT), name
        assert candidate.line_number == line, name
        assert candidate.text == lines[line - 1], name
        result = parser.parse(candidate)
        assert isinstance(result, RuleValidationResult), name
        assert result.source is candidate, name
        assert result.source.source == str(INPUT), name
        assert result.source.line_number == line, name
        assert result.status == status, (name, result.status, result.reason)
        assert isinstance(result.reason, str) and result.reason.strip(), name
        if status == "valid":
            assert isinstance(result.rule, InternalRule), name
            accepted.append(result.rule)
        else:
            assert result.rule is None, name
            assert result.reason == reason, (name, result.reason)
        results.append(result)
        detail = result.reason if status != "valid" else f"sid={result.rule.sid}"
        print(f"PASS line {line}: {name} -> {status}; {detail}")

    assert sum(result.status == "invalid" for result in results) == 9
    assert sum(result.status == "unsupported" for result in results) == 2
    assert [rule.sid for rule in accepted] == [200001, 200014]
    assert [rule.rev for rule in accepted] == [1, 1]
    assert [rule.header.protocol for rule in accepted] == ["tcp", "udp"]
    assert [rule.msg for rule in accepted] == [
        "T02 valid before errors", "T02 valid after errors",
    ]
    assert accepted[0] is results[0].rule and accepted[-1] is results[-1].rule
    assert results[0].status == results[-1].status == "valid"
    assert all(result.status != "valid" for result in results[1:-1])
    assert INPUT.read_bytes() == original
    print("PASS: rejected rules excluded; final valid rule accepted; input unchanged")
    print("Cases: 13; valid: 2; invalid: 9; unsupported: 2")
    print("T02 PASS")


if __name__ == "__main__":
    main()
