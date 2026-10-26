"""Verify flow matching with the real tracker and evidence adapter for T08."""

from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
import json
import sys


TEST_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST_DIR.parents[2]))

from core_engine.flow_context_adapter import FlowContextAdapter
from core_engine.flow_matcher import FlowMatcher
from core_engine.rule_loader import RuleLoader
from core_engine.rule_parser import RuleParserValidator
from pipeline import IDSPipeline


RULES = TEST_DIR / "sample.rules"
INPUT = TEST_DIR / "input.jsonl"
FLOW_TERMS = (
    "to_server,established", "to_client,established",
    "to_server,not_established", "to_client,not_established",
    "to_server", "to_client", "established", "not_established",
)


def sids(*suffixes) -> set[int]:
    """Expand the fixture SID suffixes."""

    return {100800 + suffix for suffix in suffixes}


def main() -> None:
    """Check conjunctions, missing evidence and real connection state."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")

    originals = {path: path.read_bytes() for path in (RULES, INPUT)}
    loader = RuleLoader()
    results = [RuleParserValidator().parse(source) for source in loader.load([RULES])]
    assert len(results) == 8 and not loader.issues
    assert all(result.status == "valid" for result in results)
    rules = {result.rule.sid: result.rule for result in results}
    assert set(rules) == set(range(100801, 100809))
    for result, terms in zip(results, FLOW_TERMS):
        assert [option.value for option in result.rule.options if option.name == "flow"] == [terms]
    rule_snapshot = {sid: asdict(rule) for sid, rule in rules.items()}
    inputs = [json.loads(line) for line in INPUT.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(inputs) == 5
    assert all("flow" not in event and "client_server_direction" not in event for event in inputs)
    pipeline, adapter = IDSPipeline(), FlowContextAdapter()
    events, contexts = [], []
    states = ["HANDSHAKE", "HANDSHAKE", "ESTABLISHED", "ESTABLISHED", "ESTABLISHED"]
    relative = ["forward", "backward", "forward", "forward", "backward"]
    roles = ["to_server", "to_client", "to_server", "to_server", "to_client"]
    expected_sets = [sids(3, 5, 8), sids(4, 6, 8), sids(1, 5, 7), sids(1, 5, 7), sids(2, 6, 7)]
    for index, original in enumerate(inputs):
        saved = deepcopy(original)
        tracked = pipeline.process_event(original)
        assert tracked is not None and tracked["flow"]["tracked"] is True
        assert original == saved
        assert tracked["flow"]["state"] == states[index]
        assert tracked["flow"]["direction"] == relative[index]
        assert "client_server_direction" not in tracked["flow"]
        assert tracked["flow"]["endpoint_a"] == {"ip": "192.168.1.10", "port": 50000}
        assert tracked["flow"]["endpoint_b"] == {"ip": "192.168.1.20", "port": 80}
        before = deepcopy(tracked)
        context = adapter.enrich(tracked, tracked["flow"])
        assert tracked == before and context["client_server_direction"] == roles[index]
        assert {key: value for key, value in context.items() if key != "client_server_direction"} == tracked["flow"]
        assert json.loads(json.dumps(context)) == context
        assert tracked["transport"]["payload_hex"] == original["transport"]["payload_hex"]
        events.append(tracked)
        contexts.append(context)
    assert len({context["flow_id"] for context in contexts}) == 1
    assert len(pipeline.flow_tracker.active_flows) == 1
    assert contexts[-1]["packet_count"] == 5
    assert contexts[-1]["forward_packet_count"] == 3 and contexts[-1]["backward_packet_count"] == 2
    assert contexts[-1]["duration"] == 4.0
    matcher = FlowMatcher()
    cases = comparisons = 0

    def check(name, event, context, expected) -> None:
        """Compare every real matcher result with a fixed expected SID set."""

        nonlocal cases, comparisons
        saved = deepcopy((event, context))
        actual = set()
        for sid, rule in rules.items():
            expected_status = "MATCH" if sid in expected else "NO_MATCH"
            status = matcher.match(rule, event, context)
            assert status == expected_status, (name, sid, status, expected_status)
            comparisons += 1
            if status == "MATCH":
                actual.add(sid)
        assert actual == expected and (event, context) == saved, name
        cases += 1
        print(f"PASS {name}: flow-matched SIDs={sorted(actual)}")

    for index, (event, context, expected) in enumerate(zip(events, contexts, expected_sets), 1):
        check(f"real tracker packet {index}: {context['state']}/{context['client_server_direction']}", event, context, expected)
    event, established = events[3], contexts[3]
    for name, context in (("missing context", None), ("empty context", {}),
                          ("list context", []), ("untracked context", {"tracked": False})):
        check(name, event, context, set())
    check("raw tracker context has no client/server role", event, event["flow"], sids(7))
    for value in ("UNKNOWN", None, "forward", "backward"):
        context = deepcopy(established)
        context["client_server_direction"] = value
        check(f"unknown role {value}", event, context, sids(7))
    for state in ("UNKNOWN", None, [], "NEW", "CLOSING", "CLOSED", "RESET"):
        context = deepcopy(established)
        context["state"] = state
        check(f"unit state policy {state}", event, context, sids(3, 5, 8) if state == "NEW" else sids(5))
    context = deepcopy(established)
    del context["state"]
    check("missing state", event, context, sids(5))
    for field, value in (("flow_id", "wrong-instance"), ("endpoint_a", None),
                         ("endpoint_b", {"ip": "203.0.113.1", "port": 80})):
        context = deepcopy(established)
        context[field] = value
        check(f"malformed context {field}", event, context, set())

    # A new adapter cannot recover the initial SYN from an established snapshot.
    unknown = FlowContextAdapter().enrich(event, event["flow"])
    assert unknown["client_server_direction"] == "UNKNOWN"
    check("fresh adapter without SYN history", event, unknown, sids(7))
    partial_pipeline, partial_adapter = IDSPipeline(), FlowContextAdapter()
    for index in (1, 2):
        tracked = partial_pipeline.process_event(inputs[index])
        assert tracked is not None and tracked["flow"]["state"] == "HANDSHAKE"
        context = partial_adapter.enrich(tracked, tracked["flow"])
        assert context["client_server_direction"] == "UNKNOWN"
        if index == 1:
            assert context["direction"] == "forward" and context["endpoint_a"]["ip"] == "192.168.1.20"
        check(f"real capture starting at SYN/ACK packet {index}", tracked, context, sids(8))
    midstream = IDSPipeline().process_event(inputs[3])
    assert midstream is not None and midstream["flow"]["state"] == "NEW"
    context = FlowContextAdapter().enrich(midstream, midstream["flow"])
    assert context["client_server_direction"] == "UNKNOWN"
    check("real midstream ACK does not prove established", midstream, context, sids(8))
    assert cases == 29 and comparisons == 232
    assert rule_snapshot == {sid: asdict(rule) for sid, rule in rules.items()}
    assert originals == {path: path.read_bytes() for path in originals}
    print(f"Cases: {cases}; exact MATCH/NO_MATCH assertions: {comparisons}; rules: 8")
    print("Integration PASS: real pipeline/FlowTracker -> SYN evidence adapter -> FlowMatcher; five-packet connection and partial captures")
    print("State policy: ESTABLISHED only; NEW/HANDSHAKE not_established; CLOSING/CLOSED/RESET neither")
    print("Scope: flow component integration; production Evaluation Engine integration not implemented")
    print("T08 PASS")


if __name__ == "__main__":
    main()
