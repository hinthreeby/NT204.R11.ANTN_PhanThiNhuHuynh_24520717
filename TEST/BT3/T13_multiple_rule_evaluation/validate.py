"""Verify multiple rule results and evaluation counters for T13."""

from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import json
import sys


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parents[2]))

from core_engine.evaluation_engine import RuleEvaluationEngine
from core_engine.models import EvaluationStatistics, MatchInformation
from core_engine.rule_loader import RuleLoader
from core_engine.rule_matching_engine import RuleMatchingEngine
from core_engine.rule_parser import RuleParserValidator
from core_engine.rule_repository import RuleRepository


RULES = TEST_DIR / "sample.rules"
INPUT = TEST_DIR / "input.jsonl"


def main() -> None:
    """Compare real engine results with fixed SID sets and byte spans."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")
    assertions = 0

    def check(condition, message) -> None:
        """Count each executed assertion."""

        nonlocal assertions
        assert condition, message
        assertions += 1

    originals = {path: path.read_bytes() for path in (RULES, INPUT)}
    loader, parser = RuleLoader(), RuleParserValidator()
    sources = loader.load([RULES])
    check(not loader.issues, "Rule Loader reported errors")
    check(len(sources) == 4, "Expected four rule candidates")
    check([source.line_number for source in sources] == [2, 3, 4, 5], "Wrong source line numbers")
    check(all(Path(source.source) == RULES for source in sources), "Wrong source filename")
    validations = [parser.parse(source) for source in sources]
    repository = RuleRepository(loader)
    for validation in validations:
        check(validation.status == "valid" and validation.rule is not None, validation.reason)
        repository.add_validated(validation)
    rules = {rule.sid: rule for rule in repository.active_rules}
    check(set(rules) == {108301, 108302, 108303, 108304}, "Wrong active rules")
    expected_messages = {
        108301: "Match GET", 108302: "Match admin path",
        108303: "Content absent", 108304: "Different port",
    }
    for sid, rule in rules.items():
        check(rule.rev == 1 and rule.msg == expected_messages[sid], f"Wrong rule identity: {sid}")
    rule_snapshot = tuple(asdict(rule) for rule in repository.active_rules)
    inputs = [json.loads(line) for line in INPUT.read_text(encoding="utf-8").splitlines() if line.strip()]
    check(len(inputs) == 1, "Expected one input event")
    original = inputs[0]
    check(original["timestamp"] == 1000.0, "Wrong timestamp")
    check(original["network"]["src_ip"] == "192.0.2.10" and original["network"]["dst_ip"] == "198.51.100.20", "Wrong IP endpoints")
    check(original["transport"]["src_port"] == 53000 and original["transport"]["dst_port"] == 80, "Wrong ports")
    check(original["transport"]["protocol"] == "TCP", "Wrong protocol")
    check(bytes.fromhex(original["transport"]["payload_hex"]) == b"GET /admin", "Raw bytes differ")
    check(original["transport"]["payload_length"] == len(b"GET /admin") == 10, "Wrong byte length")
    check(original["flow"]["endpoint_a"] == {"ip": "192.0.2.10", "port": 53000}, "Wrong endpoint A")
    check(original["flow"]["endpoint_b"] == {"ip": "198.51.100.20", "port": 80}, "Wrong endpoint B")
    check(original["flow"]["client_server_direction"] == "UNKNOWN", "Fixture must not infer client/server")

    public = deepcopy(original)
    public["packet_id"], public["timestamp"] = 2, 1001.0
    public["transport"].update(payload_hex=b"GET /public".hex(), payload_length=11)
    public["network"]["total_length"] = 51
    empty = deepcopy(original)
    empty["packet_id"], empty["timestamp"] = 3, 1002.0
    empty["transport"].update(payload_hex="", payload_length=0)
    empty["network"]["total_length"] = 40
    other_port = deepcopy(original)
    other_port["packet_id"], other_port["timestamp"] = 4, 1003.0
    other_port["transport"]["dst_port"] = 443
    other_port["flow"].update(flow_id="t13-other-port", endpoint_b={"ip": "198.51.100.20", "port": 443})
    repeat = deepcopy(original)
    repeat["packet_id"], repeat["timestamp"] = 5, 1004.0
    cases = [
        ("GET /admin", original, {108301, 108302, 108303}, {108301: (0, 3, "474554"), 108302: (4, 10, "2f61646d696e")}, (1, 3, 2)),
        ("GET /public", public, {108301, 108302, 108303}, {108301: (0, 3, "474554")}, (2, 6, 3)),
        ("empty payload", empty, {108301, 108302, 108303}, {}, (3, 9, 3)),
        ("destination port 443", other_port, {108304}, {108304: (0, 3, "474554")}, (4, 10, 4)),
        ("repeat GET /admin", repeat, {108301, 108302, 108303}, {108301: (0, 3, "474554"), 108302: (4, 10, "2f61646d696e")}, (5, 13, 6)),
    ]
    matcher = RuleMatchingEngine()
    engine = RuleEvaluationEngine(repository, matcher)
    check(engine.statistics == EvaluationStatistics(), "Counters must start at zero")
    header_information = tuple(MatchInformation(field=field) for field in (
        "transport.protocol", "network.src_ip", "transport.src_port", "network.dst_ip", "transport.dst_port",
    ))
    for name, event, expected_candidates, expected_matches, totals in cases:
        context = event["flow"]
        before = deepcopy((event, context))
        candidates = repository.candidates(event)
        check({rule.sid for rule in candidates} == expected_candidates, f"{name}: candidate SID set")
        check(len(candidates) == len(set(candidates)) == len(expected_candidates), f"{name}: duplicate candidates")
        for sid, rule in rules.items():
            verdict = matcher.match(rule, event, context)
            check(verdict.status == ("MATCH" if sid in expected_matches else "NO_MATCH"), f"{name}: rule {sid} verdict")
        previous = engine.statistics
        result = engine.evaluate(event, context)
        check(result.events_evaluated == 1, f"{name}: event count")
        check(result.candidate_rules == len(expected_candidates), f"{name}: candidate count")
        check(result.match_count == len(result.matches) == len(expected_matches), f"{name}: match count")
        actual_sids = [match.rule.sid for match in result.matches]
        check(set(actual_sids) == set(expected_matches), f"{name}: exact matched SID set")
        check(len(actual_sids) == len(set(actual_sids)), f"{name}: duplicate match results")
        check(108303 not in actual_sids, f"{name}: absent content matched")
        for match in result.matches:
            sid = match.rule.sid
            check(match.rule is rules[sid], f"{name}: original rule object lost")
            check(match.status == "MATCH" and match.rule.rev == 1, f"{name}: status/revision")
            check(match.rule.msg == expected_messages[sid], f"{name}: message")
            start, end, raw_hex = expected_matches[sid]
            expected_information = header_information + (MatchInformation(
                field="transport.payload_hex", start=start, end=end,
                matched_hex=raw_hex, option_index=1,
            ),)
            check(match.information == expected_information, f"{name}: field information or byte spans differ")
            check(bytes.fromhex(event["transport"]["payload_hex"])[start:end] == bytes.fromhex(raw_hex), f"{name}: matched raw bytes")
        check(engine.statistics == EvaluationStatistics(*totals), f"{name}: cumulative counters")
        check(engine.statistics.events_evaluated_total == previous.events_evaluated_total + 1, f"{name}: event counted more than once")
        check((event, context) == before, f"{name}: input changed")
        check(tuple(asdict(rule) for rule in repository.active_rules) == rule_snapshot, f"{name}: stored rules changed")
        print(f"PASS {name}: candidates={sorted(expected_candidates)}, matches={sorted(actual_sids)}, per-event=(1,{result.candidate_rules},{result.match_count}), totals={totals}")
    check(all(path.read_bytes() == content for path, content in originals.items()), "Input files changed")
    print(f"T13 PASS: {len(cases)} scenarios, {assertions} assertions; events=5, candidates=13, matches=6")


if __name__ == "__main__":
    main()
