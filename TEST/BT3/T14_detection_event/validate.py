"""Verify detection fields, source errors and pipeline JSONL for T14."""

import argparse
from copy import deepcopy
from dataclasses import asdict
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory


TEST_DIR = Path(__file__).resolve().parent
ROOT = TEST_DIR.parents[2]
sys.path.insert(0, str(ROOT))

from config import IDSConfig
from core_engine.detection_event import DetectionEventDataError, DetectionEventGenerator
from core_engine.evaluation_engine import RuleEvaluationEngine
from core_engine.rule_loader import RuleLoader
from core_engine.rule_matching_engine import RuleMatchingEngine
from core_engine.rule_parser import RuleParserValidator
from core_engine.rule_repository import RuleRepository
from output.jsonl_writer import JSONLWriter
from pipeline import IDSPipeline


RULES, INPUT, OUTPUT = (TEST_DIR / name for name in ("sample.rules", "input.jsonl", "result.jsonl"))
MESSAGES = {
    101401: "HTTP admin detected", 101402: "HTTP GET detected", 101403: "Different port",
    101404: "Flow only", 101405: "Packet only", 101406: "Relative contents",
}


def information(field, start=None, end=None, raw=None, index=None) -> dict:
    """Describe expected evidence without calling production conversion code."""

    return {"field": field, "start": start, "end": end, "matched_hex": raw, "option_index": index}


HEADER = [information(field) for field in (
    "transport.protocol", "network.src_ip", "transport.src_port", "network.dst_ip", "transport.dst_port",
)]
EVIDENCE = {
    101401: HEADER + [information("transport.payload_hex", 4, 10, "2f61646d696e", 1)],
    101402: HEADER + [information("transport.payload_hex", 0, 3, "474554", 1)],
    101404: HEADER + [information("flow.client_server_direction", index=1), information("flow.state", index=1)],
    101405: HEADER + [information("transport.flags", index=1), information("transport.payload_length", index=2)],
    101406: HEADER + [information("transport.payload_hex", 0, 3, "474554", 1), information("transport.payload_hex", 4, 10, "2f61646d696e", 2)],
}


def expected(sid, flow_id="t14-fixture-flow", timestamp=1000.0) -> dict:
    """Build fixed expected fields from the published fixtures."""

    return {
        "timestamp": timestamp, "sid": sid, "rev": 1, "msg": MESSAGES[sid],
        "src_ip": "192.0.2.10", "src_port": 53000, "dst_ip": "198.51.100.20", "dst_port": 80,
        "protocol": "TCP", "application_protocol": "HTTP", "flow_id": flow_id,
        "match_information": EVIDENCE[sid],
        "priority": 2 if sid == 101401 else None,
        "classtype": "web-application-attack" if sid == 101401 else None,
    }


def main(write_output: bool) -> None:
    """Assert exact detections through real components and CLI integration."""

    if not __debug__:
        raise RuntimeError("Run without -O so assertions remain enabled")
    assertions = scenarios = 0

    def check(condition, message) -> None:
        nonlocal assertions
        assert condition, message
        assertions += 1

    originals = {path: path.read_bytes() for path in (RULES, INPUT)}
    loader, parser, generator = RuleLoader(), RuleParserValidator(), DetectionEventGenerator()
    validations = [parser.parse(source) for source in loader.load([RULES])]
    check(len(validations) == 6 and not loader.issues, "Expected six loaded rules")
    check(all(result.status == "valid" for result in validations), "Rule validation failed")
    rules = {result.rule.sid: result.rule for result in validations}
    check(set(rules) == set(MESSAGES), "Wrong fixture SIDs")
    rule_snapshot = {sid: asdict(rule) for sid, rule in rules.items()}
    inputs = [json.loads(line) for line in INPUT.read_text(encoding="utf-8").splitlines() if line.strip()]
    check(len(inputs) == 1, "Expected one input event")
    event = inputs[0]
    check(bytes.fromhex(event["transport"]["payload_hex"]) == b"GET /admin", "Wrong raw payload")
    check(event["transport"]["payload_length"] == len(b"GET /admin") == 10, "Wrong payload length")

    def verify(record, fixed) -> None:
        check(set(record) == set(fixed), "Detection field set differs")
        for field, value in fixed.items():
            check(record[field] == value, f"Wrong {field}")
            check(type(record[field]) is type(value), f"Wrong type for {field}")
        for info in record["match_information"]:
            check(type(info) is dict, "Evidence must be a JSON object")
            for field in ("start", "end", "option_index"):
                check(info[field] is None or type(info[field]) is int, f"Wrong evidence type: {field}")
            check(info["matched_hex"] is None or type(info["matched_hex"]) is str, "Invalid matched_hex type")
        check(json.loads(json.dumps(record, ensure_ascii=False, allow_nan=False)) == record, "JSON round trip failed")

    def evaluate(name, selected, source, expected_sids):
        nonlocal scenarios
        repo = RuleRepository(loader)
        for validation in validations:
            if validation.rule.sid in selected:
                repo.add_validated(validation)
        matcher = RuleMatchingEngine()
        check({rule.sid for rule in repo.candidates(source)} == set(selected) - {101403}, f"{name}: indexed candidates")
        for sid in selected:
            check(matcher.match(rules[sid], source, source["flow"]).status == ("MATCH" if sid in expected_sids else "NO_MATCH"), f"{name}: matcher verdict")
        before = deepcopy(source)
        result = RuleEvaluationEngine(repo, matcher).evaluate(source, source["flow"])
        check([match.rule.sid for match in result.matches] == expected_sids, f"{name}: evaluation SIDs")
        detections = generator.generate_all(source, source["flow"], result)
        check(len(detections) == len(expected_sids), f"{name}: detection count")
        for detection, match in zip(detections, result.matches):
            check(detection.match_information == match.information, f"{name}: evidence lost")
            verify(generator.to_dict(detection), expected(detection.sid))
        check(source == before, f"{name}: input mutated")
        scenarios += 1
        print(f"PASS {name}: SIDs={expected_sids}")
        return result, detections

    single, _ = evaluate("single rule with classification", [101401], event, [101401])
    evaluate("two simultaneous rules and wrong-port exclusion", [101401, 101402, 101403], event, [101401, 101402])
    evaluate("packet-only detection", [101405], event, [101405])
    evaluate("multiple positional contents", [101406], event, [101406])
    absent = deepcopy(event)
    absent["transport"].update(payload_hex=b"nothing".hex(), payload_length=7)
    absent["network"]["total_length"] = 47
    evaluate("no matching content", [101401, 101402, 101403], absent, [])
    check(generator.generate_all(event, event["flow"], None) == (), "Missing matches must produce no detections")
    scenarios += 1

    for section, field in ((None, "timestamp"), ("network", "src_ip"), ("network", "dst_ip"), ("transport", "src_port"), ("transport", "dst_port"), ("transport", "protocol")):
        broken = deepcopy(event)
        del (broken if section is None else broken[section])[field]
        snapshot = deepcopy(broken)
        try:
            generator.generate_all(broken, broken["flow"], single)
        except DetectionEventDataError as exc:
            check(field in str(exc), f"Missing {field}: unclear error")
        else:
            raise AssertionError(f"Missing {field} accepted")
        check(broken == snapshot, "Error handling mutated input")
        scenarios += 1
    for value in (None, "not-an-ip"):
        broken = deepcopy(event)
        broken["network"]["src_ip"] = value
        try:
            generator.generate(broken, broken["flow"], single.matches[0])
        except DetectionEventDataError as exc:
            check("src_ip" in str(exc), "Malformed source error lacks field")
        else:
            raise AssertionError("Malformed source accepted")
        scenarios += 1

    for name, context in (("missing tracked flow ID", {"tracked": True}),
                          ("conflicting flow ID", {"tracked": True, "flow_id": "other-flow"})):
        try:
            generator.generate(event, context, single.matches[0])
        except DetectionEventDataError as exc:
            check("flow_id" in str(exc), f"{name}: unclear error")
        else:
            raise AssertionError(f"{name} accepted")
        scenarios += 1

    with TemporaryDirectory(prefix="ids-t14-") as directory:
        temporary = Path(directory)
        normalized, detections = temporary / "events.jsonl", temporary / "detections.jsonl"
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8")
        command = [sys.executable, "-B", str(ROOT / "main.py"), "--input", str(INPUT), "--output", str(normalized),
                   "--enable-core-engine", "--rules", str(RULES), "--detection-output", str(detections)]
        for sid in (101404, 101405, 101406):
            command.extend(("--disable-rule", str(sid)))
        completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8")
        check(completed.returncode == 0, completed.stdout + completed.stderr)
        tracked = [json.loads(line) for line in normalized.read_text(encoding="utf-8").splitlines()]
        check(len(tracked) == 1 and tracked[0]["flow"]["tracked"] is True, "Pipeline did not track source")
        flow_id = tracked[0]["flow"]["flow_id"]
        check(type(flow_id) is str and flow_id.startswith("flow-"), "Missing real tracker flow ID")
        check(tracked[0]["timestamp"] == 1000.0, "Pipeline timestamp changed")
        check(tracked[0]["transport"]["payload_hex"] == "474554202f61646d696e", "Pipeline raw bytes changed")
        check("match_information" not in tracked[0], "Detection mixed into normalized event")
        jsonl = detections.read_bytes()
        records = [json.loads(line) for line in jsonl.decode("utf-8").splitlines()]
        check(len(records) == 2, "One input event must produce two JSONL objects")
        check([record["sid"] for record in records] == [101401, 101402], "Wrong pipeline detections or duplicates")
        for record in records:
            verify(record, expected(record["sid"], flow_id))
        scenarios += 1
        print("PASS CLI pipeline: one source event, two detection JSONL objects")

        config = IDSConfig(core_engine_enabled=True, rule_files=(str(RULES),), disabled_rule_sids=(101401, 101402, 101403, 101405, 101406))
        syn = deepcopy(event)
        syn.pop("flow")
        syn["timestamp"] = 2000.0
        syn["transport"].update(flags=["SYN"], payload_hex="", payload_length=0)
        syn["network"]["total_length"] = 40
        snapshot = deepcopy(syn)
        with JSONLWriter(str(temporary / "flow.jsonl")) as writer:
            pipeline = IDSPipeline(config, detection_sink=writer.write_event)
            source = pipeline.process_event(syn)
        check(syn == snapshot and source["flow"]["state"] == "HANDSHAKE", "SYN tracking or input changed")
        written = [json.loads(line) for line in (temporary / "flow.jsonl").read_text(encoding="utf-8").splitlines()]
        check(len(written) == 1, "Flow-only rule must generate one detection")
        verify(written[0], expected(101404, source["flow"]["flow_id"], 2000.0))
        scenarios += 1
        print("PASS flow-only pipeline: real SYN evidence, no fabricated content spans")

        rejected = []
        invalid_pipeline = IDSPipeline(IDSConfig(core_engine_enabled=True, rule_files=(str(RULES),)), detection_sink=rejected.append)
        malformed = deepcopy(event)
        malformed.pop("timestamp")
        processed = invalid_pipeline.process_event(malformed)
        check(processed is not None and processed["preprocess_status"] == "invalid", "Invalid source policy changed")
        check(not rejected and not invalid_pipeline.last_core_result.detection_events, "Invalid source produced detection")
        scenarios += 1

    check(not Path(directory).exists(), "Temporary files remain")
    check(all(path.read_bytes() == original for path, original in originals.items()), "Input files changed")
    check({sid: asdict(rule) for sid, rule in rules.items()} == rule_snapshot, "Rules mutated")
    if write_output:
        OUTPUT.write_bytes(jsonl)
    check(OUTPUT.read_bytes() == jsonl, "Saved result.jsonl differs from actual CLI output")
    print(f"T14 PASS: {scenarios} scenarios, {assertions} assertions; JSONL, multiple detections and pipeline integration PASS")


if __name__ == "__main__":
    arguments = argparse.ArgumentParser()
    arguments.add_argument("--write-output", action="store_true", help="Refresh T14 result.jsonl after successful checks")
    main(arguments.parse_args().write_output)
