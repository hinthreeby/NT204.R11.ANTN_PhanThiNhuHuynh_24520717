"""Verify rule loading and validation for official testcase T01."""

from pathlib import Path
import sys


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parents[2]))

from core_engine.models import InternalRule, RuleText
from core_engine.rule_loader import RuleLoader, RuleLoaderConfig
from core_engine.rule_parser import RuleParserValidator


SAMPLE = TEST_DIR / "sample.rules"
ADDITIONAL = TEST_DIR / "additional.rules"

EXPECTED_SAMPLE = (
    (SAMPLE, 3, 'alert tcp any any -> 192.0.2.10 80 (msg:"T01 HTTP"; content:"GET /"; sid:100001; rev:1;)'),
    (SAMPLE, 6, '  alert udp any any -> 192.0.2.53 53 (msg:"T01 DNS # marker; unchanged"; sid:100002; rev:1;)'),
    (SAMPLE, 8, 'alert tcp 198.51.100.0/24 1024:65535 <> 192.0.2.25 25 (msg:"T01 SMTP"; sid:100003; rev:1;)'),
)
EXPECTED_ADDITIONAL = (
    (ADDITIONAL, 3, 'alert tcp any any -> any 443 (msg:"T01 first additional rule"; sid:100004; rev:1;)'),
    (ADDITIONAL, 4, 'alert tcp any any -> any 80 (msg:"T01 invalid SID"; sid:not_an_integer; rev:1;)'),
    (ADDITIONAL, 6, 'alert udp any any <> any 5353 (msg:"T01 last additional rule"; sid:100005; rev:1;)'),
)


def check_candidates(candidates: list[RuleText], expected: tuple) -> None:
    """Check exact candidate text and source locations."""

    assert len(candidates) == len(expected), "Unexpected candidate count"
    for candidate, (path, line_number, text) in zip(candidates, expected):
        assert isinstance(candidate, RuleText)
        assert candidate.source == str(path), "Incorrect source filename"
        assert candidate.line_number == line_number, "Incorrect source line"
        assert candidate.text == text, "Rule text was lost or changed"


def main() -> None:
    """Run all T01 assertions."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")

    original = {path: path.read_bytes() for path in (SAMPLE, ADDITIONAL)}
    lines = SAMPLE.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 9
    assert [i for i, line in enumerate(lines, 1) if not line.strip()] == [2, 5, 7]
    assert [i for i, line in enumerate(lines, 1) if line.lstrip().startswith("#")] == [1, 4, 9]

    loader = RuleLoader()
    parser = RuleParserValidator()
    candidates = loader.load([SAMPLE])
    check_candidates(candidates, EXPECTED_SAMPLE)
    assert not loader.issues
    print("PASS 1: comments/blanks filtered; exact text, filename and line number retained")

    sample_results = [parser.parse(candidate) for candidate in candidates]
    assert [result.status for result in sample_results] == ["valid"] * 3
    assert [result.rule.sid for result in sample_results] == [100001, 100002, 100003]
    assert [result.source for result in sample_results] == candidates
    assert all(isinstance(result.rule, InternalRule) for result in sample_results)
    assert sample_results[1].rule.msg == "T01 DNS # marker; unchanged"
    print("PASS 2: all three sample rules accepted by the real Validator")

    candidates = loader.load([SAMPLE, ADDITIONAL])
    check_candidates(candidates, EXPECTED_SAMPLE + EXPECTED_ADDITIONAL)
    assert not loader.issues
    results = [parser.parse(candidate) for candidate in candidates]
    assert [result.status for result in results] == [
        "valid", "valid", "valid", "valid", "invalid", "valid",
    ]
    assert [result.source for result in results] == candidates
    assert all(result.reason for result in results)
    print("PASS 3: two files produce six ordered candidates, five valid and one invalid")

    file_policies = (
        ({ADDITIONAL: False}, EXPECTED_SAMPLE),
        ({SAMPLE: False}, EXPECTED_ADDITIONAL),
        ({SAMPLE: True, ADDITIONAL: True}, EXPECTED_SAMPLE + EXPECTED_ADDITIONAL),
        ({SAMPLE: False, ADDITIONAL: False}, ()),
    )
    for switches, expected in file_policies:
        configured = RuleLoader(RuleLoaderConfig(file_enabled=switches))
        check_candidates(configured.load([SAMPLE, ADDITIONAL]), expected)
        assert not configured.issues
    print("PASS 4: explicit file enable/disable and default enable policies")

    configured = RuleLoader(RuleLoaderConfig(rule_enabled={100002: False, 100004: True}))
    candidates = configured.load([SAMPLE, ADDITIONAL])
    check_candidates(candidates, EXPECTED_SAMPLE + EXPECTED_ADDITIONAL)
    results = [parser.parse(candidate) for candidate in candidates]
    assert results[1].status == "valid" and results[1].rule.sid == 100002
    assert configured.is_rule_enabled(results[1].rule) is False
    accepted = [
        result.rule for result in results
        if result.status == "valid" and configured.is_rule_enabled(result.rule)
    ]
    assert [rule.sid for rule in accepted] == [100001, 100003, 100004, 100005]
    enabled = RuleLoader(RuleLoaderConfig(rule_enabled={100002: True}))
    assert [
        result.rule.sid for result in results
        if result.status == "valid" and enabled.is_rule_enabled(result.rule)
    ] == [100001, 100002, 100003, 100004, 100005]
    print("PASS 5: SID policy applied only after validation; disabled candidate remains intact")

    assert results[3].status == "valid" and results[3].rule.sid == 100004
    assert results[4].status == "invalid" and results[4].rule is None
    assert results[4].reason == "sid requires a decimal integer"
    assert results[4].source.source == str(ADDITIONAL)
    assert results[4].source.line_number == 4
    assert results[5].status == "valid" and results[5].rule.sid == 100005
    assert accepted[-1] is results[5].rule
    assert not configured.issues
    assert original == {path: path.read_bytes() for path in original}
    print("PASS 6: invalid middle rule rejected; later rule accepted; input fixtures unchanged")
    print("T01 PASS")


if __name__ == "__main__":
    main()
