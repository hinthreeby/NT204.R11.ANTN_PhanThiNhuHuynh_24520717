"""Verify unsupported keyword handling for official testcase T03."""

from pathlib import Path
import sys


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parents[2]))

from core_engine.models import InternalRule, RuleValidationResult
from core_engine.rule_loader import RuleLoader
from core_engine.rule_parser import RuleParserValidator


INPUT = TEST_DIR / "unsupported.rules"
EXPECTED = (
    (2, "supported content/nocase", "valid", None),
    (3, "pcre", "unsupported", "Unsupported options: pcre"),
    (4, "byte_test", "unsupported", "Unsupported options: byte_test"),
    (5, "byte_jump", "unsupported", "Unsupported options: byte_jump"),
    (6, "unknown keyword", "unsupported", "Unsupported options: future_keyword"),
    (7, "multiple unsupported keywords", "unsupported",
     "Unsupported options: pcre, byte_test, byte_jump, future_keyword"),
    (8, "keyword names inside quoted content", "valid", None),
    (9, "pcre before invalid SID", "invalid", "sid requires a decimal integer"),
    (10, "invalid SID before pcre", "invalid", "sid requires a decimal integer"),
    (11, "unclosed quote with pcre", "invalid",
     "Unclosed quote/escape or missing closing parenthesis"),
    (12, "missing revision with pcre", "invalid", "Missing required options: rev"),
    (13, "all mandatory option keywords", "valid", None),
    (14, "valid rule after errors", "valid", None),
)
SUPPORTED_OPTIONS = {
    "msg", "sid", "rev", "content", "nocase", "offset", "depth", "distance",
    "within", "flags", "dsize", "flow", "classtype", "priority",
}


def main() -> None:
    """Check unsupported diagnostics and continued rule processing."""

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

    results = {}
    active_valid_rules = []
    for candidate, (line, name, status, reason) in zip(candidates, EXPECTED):
        assert candidate.source == str(INPUT), name
        assert candidate.line_number == line, name
        assert candidate.text == lines[line - 1], name
        result = parser.parse(candidate)
        assert isinstance(result, RuleValidationResult), name
        assert result.source is candidate, name
        assert result.status == status, (name, result.status, result.reason)
        assert isinstance(result.reason, str) and result.reason.strip(), name
        if status == "valid":
            assert isinstance(result.rule, InternalRule), name
            assert loader.is_rule_enabled(result.rule), name
            active_valid_rules.append(result.rule)
        else:
            assert result.rule is None, name
            assert result.reason == reason, (name, result.reason)
        results[line] = result
        detail = result.reason if status != "valid" else f"sid={result.rule.sid}"
        print(f"PASS line {line}: {name} -> {status}; {detail}")

    assert sum(result.status == "unsupported" for result in results.values()) == 5
    assert sum(result.status == "invalid" for result in results.values()) == 4
    assert [rule.sid for rule in active_valid_rules] == [300002, 300008, 300013, 300014]
    assert {id(rule) for rule in active_valid_rules} == {
        id(result.rule) for result in results.values() if result.status == "valid"
    }
    assert results[2].status == results[8].status == results[14].status == "valid"
    assert all(results[line].status == "unsupported" for line in range(3, 8))

    quoted = results[8].rule
    assert [option.name for option in quoted.options] == [
        "msg", "content", "nocase", "sid", "rev",
    ]
    assert quoted.options[1].value == r'"pcre:\"literal\"; byte_test; byte_jump; future_keyword"'
    supported = results[13].rule
    assert {option.name for option in supported.options} == SUPPORTED_OPTIONS
    assert sum(option.name == "content" for option in supported.options) == 2
    assert supported.priority == 1 and supported.classtype == "web-application-attack"
    assert results[9].reason == results[10].reason == "sid requires a decimal integer"
    assert INPUT.read_bytes() == original
    print("PASS: quoted names preserved; supported keywords accepted; invalid syntax takes priority")
    print("Accepted valid SIDs: 300002, 300008, 300013, 300014")
    print("Cases: 13; valid: 4; unsupported: 5; invalid: 4")
    print("T03 PASS")


if __name__ == "__main__":
    main()
