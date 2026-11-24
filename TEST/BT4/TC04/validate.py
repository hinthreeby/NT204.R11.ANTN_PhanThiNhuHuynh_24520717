"""Verify severity thresholds before alert creation."""

from copy import deepcopy
from pathlib import Path
import sys
from unittest.mock import patch
from uuid import UUID, uuid4


sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from alert import AlertFilterConfig, AlertManager, SeverityConfig


def event(priority=2) -> dict:
    return dict(timestamp=1000.0, sid=44004, rev=1, msg="Severity filter",
                src_ip="192.0.2.10", src_port=50000, dst_ip="198.51.100.20", dst_port=80,
                protocol="TCP", application_protocol="HTTP", flow_id="tc04-flow",
                priority=priority, match_information=[{"field": "transport.protocol"}])


def main() -> None:
    if not __debug__:
        raise RuntimeError("Run without -O")
    assertions = scenarios = 0

    def check(condition, message):
        nonlocal assertions
        assert condition, message
        assertions += 1

    def verify(manager, source, status, expected_severity=None, expected_reason=None):
        nonlocal scenarios
        before = deepcopy(source)
        with patch("alert.models.uuid4", wraps=uuid4) as identifiers:
            result = manager.process(source)
            check(result.status == status, f"Expected {status}, got {result}")
            check(identifiers.call_count == (1 if status == "created" else 0), "Wrong UUID allocation")
        check(source == before, "Detection Event mutated")
        if status == "created":
            check(result.alert is not None and result.reason is None, "Wrong created contract")
            check(result.alert.severity == expected_severity, "Severity mapping changed")
            check(UUID(result.alert.alert_id).version == 4, "Expected UUID4")
            check(result.alert.count == 1 and result.alert.flow_id == "tc04-flow", "Source identity/count changed")
        else:
            check(result.alert is None, "Filtered event created an Alert")
            check(result.reason == expected_reason, "Wrong filtering reason")
        scenarios += 1

    expected_levels = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
    allowed = {None: {1, 2, 3, 4}, "LOW": {1, 2, 3, 4}, "MEDIUM": {1, 2, 3},
               "HIGH": {1, 2}, "CRITICAL": {1}}
    for minimum, accepted in allowed.items():
        manager = AlertManager(filter_config=AlertFilterConfig(minimum_severity=minimum))
        for priority, severity in expected_levels.items():
            status = "created" if priority in accepted else "filtered"
            verify(manager, event(priority), status, severity,
                   f"Severity {severity} is below minimum {minimum}")
        print(f"PASS minimum={minimum}: accepted priorities={sorted(accepted)}")

    manager = AlertManager(filter_config=AlertFilterConfig(minimum_severity=" medium "))
    check(manager.filter_config.minimum_severity == "MEDIUM", "Threshold not normalized")
    verify(manager, event(4), "filtered", expected_reason="Severity LOW is below minimum MEDIUM")
    for minimum in ("HIGH", "MEDIUM"):
        manager = AlertManager(filter_config=AlertFilterConfig(minimum_severity=minimum))
        for missing in (False, True):
            source = event(None)
            if missing:
                del source["priority"]
            verify(manager, source, "filtered" if minimum == "HIGH" else "created", "MEDIUM",
                   "Severity MEDIUM is below minimum HIGH")
    custom = SeverityConfig({1: "LOW", 4: "CRITICAL"}, missing_severity="HIGH", unmapped_severity="MEDIUM")
    manager = AlertManager(custom, filter_config=AlertFilterConfig(minimum_severity="HIGH"))
    for priority, status, severity in ((1, "filtered", "LOW"), (4, "created", "CRITICAL"),
                                       (None, "created", "HIGH"), (99, "filtered", "MEDIUM")):
        verify(manager, event(priority), status, severity, f"Severity {severity} is below minimum HIGH")
    source = event(4)
    manager = AlertManager(filter_config=AlertFilterConfig(minimum_severity="CRITICAL"))
    for field, value in (("sid", True), ("priority", 0)):
        broken = dict(source, **{field: value})
        with patch("alert.models.uuid4", side_effect=AssertionError("UUID allocated for invalid event")):
            result = manager.process(broken)
        check(result.status == "rejected" and result.alert is None, "Invalid data classified as filtered")
        check(field in result.reason, "Unclear validation reason")
        scenarios += 1
    for minimum in ("UNKNOWN", "", " ", True, 2, [], {}):
        try:
            AlertFilterConfig(minimum_severity=minimum)
        except ValueError as exc:
            check("minimum_severity" in str(exc), "Unclear configuration error")
        else:
            raise AssertionError(f"Invalid threshold accepted: {minimum}")
        scenarios += 1
    try:
        AlertManager(filter_config={})
    except TypeError as exc:
        check("AlertFilterConfig" in str(exc), "Unclear manager config error")
    else:
        raise AssertionError("Wrong filter config type accepted")
    scenarios += 1
    print("PASS missing/null priority, custom severity mapping, invalid config and validation precedence")
    print("PASS filtered events allocate no UUID and do not mutate the source")
    print(f"TC04 PASS: {scenarios} scenarios; {assertions} assertions")


if __name__ == "__main__":
    main()
