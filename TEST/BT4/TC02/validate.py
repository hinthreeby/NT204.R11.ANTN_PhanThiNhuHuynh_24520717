"""Verify configured severity mapping and explicit fallback policies."""

from copy import deepcopy
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from alert import AlertManager, SeverityConfig


def event() -> dict:
    return dict(timestamp=1000.0, sid=42002, rev=1, msg="Severity input",
                src_ip="192.0.2.1", src_port=0, dst_ip="198.51.100.2", dst_port=65535,
                protocol="TCP", application_protocol="UNKNOWN", flow_id=None,
                match_information=[{"field": "transport.protocol"}])


def main() -> None:
    if not __debug__:
        raise RuntimeError("Run without -O")
    assertions = scenarios = 0

    def check(condition, message):
        nonlocal assertions
        assert condition, message
        assertions += 1

    manager = AlertManager()
    for priority, expected in ((1, "CRITICAL"), (2, "HIGH"), (3, "MEDIUM"), (4, "LOW"),
                               (5, "LOW"), (999, "LOW"), (None, "MEDIUM")):
        source = event()
        source["priority"] = priority
        before = deepcopy(source)
        for _ in range(2):
            result = manager.process(source)
            check(result.status == "created" and result.reason is None, "Valid priority rejected")
            check(result.alert.severity == expected and result.alert.priority == priority, "Wrong severity or source priority")
        check(source == before, "Source mutated")
        scenarios += 1
    result = manager.process(event())
    check(result.status == "created" and result.alert.priority is None, "Missing priority was fabricated")
    check(result.alert.severity == "MEDIUM", "Wrong missing-priority fallback")
    scenarios += 1
    mapping = {1: "LOW", 2: "CRITICAL", 8: "HIGH"}
    configured = SeverityConfig(mapping, missing_severity="LOW", unmapped_severity="HIGH")
    custom = AlertManager(configured)
    mapping[1] = "MEDIUM"
    for priority, expected in ((1, "LOW"), (2, "CRITICAL"), (8, "HIGH"), (3, "HIGH"), (None, "LOW")):
        source = event()
        source["priority"] = priority
        result = custom.process(source)
        check(result.status == "created" and result.alert.severity == expected, "Custom mapping/fallback not applied")
        scenarios += 1
    try:
        configured.priority_mapping[1] = "HIGH"
    except TypeError:
        check(True, "Mapping snapshot is immutable")
    else:
        raise AssertionError("Mutable mapping exposed")
    scenarios += 1
    for priority in (True, False, 0, -1, 2.5, "2", [], {}, float("nan"), float("inf")):
        source = event()
        source["priority"] = priority
        result = manager.process(source)
        check(result.status == "rejected" and result.alert is None, "Invalid priority treated as fallback")
        check(isinstance(result.reason, str) and "priority" in result.reason, "Unclear rejection")
        scenarios += 1
    for kwargs in (
        {"priority_mapping": {True: "HIGH"}}, {"priority_mapping": {0: "HIGH"}},
        {"priority_mapping": {1: "UNKNOWN"}}, {"priority_mapping": []},
        {"missing_severity": "UNKNOWN"}, {"unmapped_severity": []},
    ):
        try:
            SeverityConfig(**kwargs)
        except ValueError as exc:
            check(bool(str(exc)), "Config error lacks reason")
        else:
            raise AssertionError(f"Invalid config accepted: {kwargs}")
        scenarios += 1
    check(manager.process(event()).status == "created", "Invalid data corrupted manager state")
    print("PASS default mapping: 1 CRITICAL, 2 HIGH, 3 MEDIUM, >=4 LOW; missing/null MEDIUM")
    print("PASS custom mapping, separate fallbacks and immutable configuration snapshot")
    print("PASS malformed priorities rejected; configuration errors explicitly reported")
    print(f"TC02 PASS: {scenarios} scenarios; {assertions} assertions")


if __name__ == "__main__":
    main()
