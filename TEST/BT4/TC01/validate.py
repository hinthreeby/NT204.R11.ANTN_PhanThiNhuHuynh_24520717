"""Verify alert creation using real BT3 detections and the pipeline hook."""

from copy import deepcopy
import json
from pathlib import Path
import sys
from uuid import UUID


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from alert import Alert, AlertManager
from config import IDSConfig
from pipeline import IDSPipeline


def main() -> None:
    if not __debug__:
        raise RuntimeError("Run without -O")
    assertions = 0

    def check(condition, message):
        nonlocal assertions
        assert condition, message
        assertions += 1

    source_dir = ROOT / "TEST/BT3/T14_detection_event"
    event = json.loads((source_dir / "input.jsonl").read_text(encoding="utf-8"))
    original = deepcopy(event)
    manager = AlertManager()
    detections, alerts = [], []

    def sink(detection):
        before = deepcopy(detection)
        result = manager.process(detection)
        check(result.status == "created" and result.reason is None, "Valid detection rejected")
        check(isinstance(result.alert, Alert), "Expected Alert Object")
        check(detection == before, "Detection input mutated")
        detections.append(deepcopy(detection))
        alerts.append(result.alert)

    config = IDSConfig(
        core_engine_enabled=True,
        rule_files=(str(source_dir / "sample.rules"),),
        disabled_rule_sids=(101404, 101405, 101406),
    )
    pipeline = IDSPipeline(config, detection_sink=sink)
    normalized = pipeline.process_event(event)
    check(event == original, "Normalized input mutated")
    check(normalized is not None and normalized["flow"]["tracked"], "Real FlowTracker was not used")
    check(len(alerts) == len(detections) == 2, "Two matches must create two independent alerts")
    check([a.sid for a in alerts] == [101401, 101402], "Wrong alert SIDs")
    expected_messages = ["HTTP admin detected", "HTTP GET detected"]
    for index, (alert, detection) in enumerate(zip(alerts, detections)):
        expected = {
            "timestamp": 1000.0, "sid": 101401 + index, "rev": 1,
            "message": expected_messages[index], "severity": "HIGH" if index == 0 else "MEDIUM",
            "src_ip": "192.0.2.10", "src_port": 53000, "dst_ip": "198.51.100.20", "dst_port": 80,
            "protocol": "TCP", "application_protocol": "HTTP", "flow_id": normalized["flow"]["flow_id"],
            "priority": 2 if index == 0 else None,
            "classtype": "web-application-attack" if index == 0 else None,
            "first_seen": 1000.0, "last_seen": 1000.0, "count": 1,
        }
        record = alert.to_dict()
        check(set(record) == set(expected) | {"alert_id", "match_information"}, "Wrong Alert field set")
        for key, value in expected.items():
            check(record[key] == value and type(record[key]) is type(value), f"Wrong {key}")
        check(UUID(alert.alert_id).version == 4, "Expected UUID4")
        check(record["match_information"] == detection["match_information"], "Match evidence lost")
        content = record["match_information"][-1]
        check((content["start"], content["end"], content["matched_hex"]) ==
              ((4, 10, "2f61646d696e") if index == 0 else (0, 3, "474554")), "Wrong byte evidence")
        check(json.loads(json.dumps(record, allow_nan=False)) == record, "JSON serialization differs")
        record["match_information"][0]["field"] = "changed"
        check(alert.match_information[0]["field"] == "transport.protocol", "Export aliases Alert evidence")
        check(detection["match_information"][0]["field"] == "transport.protocol", "Export aliases source evidence")

    detection = deepcopy(detections[0])
    detection.update(msg="  HTTP admin detected  ", protocol=" tcp ", application_protocol=" http ",
                     src_ip=" 192.0.2.10 ", flow_id=" original-flow-id ")
    before = deepcopy(detection)
    result = manager.process(detection)
    check(result.status == "created", "Supported normalization rejected")
    check(result.alert.message == "HTTP admin detected" and result.alert.protocol == "TCP", "Text not normalized")
    check(result.alert.src_ip == "192.0.2.10" and result.alert.application_protocol == "HTTP", "Endpoints/protocol not normalized")
    check(result.alert.flow_id == " original-flow-id ", "Source flow identity changed")
    check(detection == before, "Normalization mutated source")
    created = [manager.process(detections[0]).alert for _ in range(2000)]
    ids = [a.alert_id for a in created] + [a.alert_id for a in alerts]
    check(len(ids) == len(set(ids)) == 2002, "Duplicate alert IDs")
    check(all(UUID(identifier).version == 4 for identifier in ids), "Invalid generated UUID")
    check(all(a.flow_id == detections[0]["flow_id"] and a.count == 1 for a in created), "IDs changed flow identity or aggregated alerts")
    saved = deepcopy(detections[0])
    created[0].match_information[0]["field"] = "detached"
    check(detections[0] == saved and created[1].match_information[0]["field"] == "transport.protocol", "Evidence aliases inputs/other alerts")
    print("PASS real pipeline -> DetectionEventGenerator dictionary -> AlertManager: two correct alerts")
    print("PASS normalization, nullable classification, preserved source/flow/evidence and JSON serialization")
    print("PASS 2002 distinct UUID4 identifiers; no implicit aggregation")
    print(f"TC01 PASS: 4 scenarios; {assertions} assertions")


if __name__ == "__main__":
    main()
