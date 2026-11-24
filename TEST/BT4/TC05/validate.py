"""Verify configured SID suppression and its precedence over filtering."""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
from unittest.mock import patch
from uuid import UUID


sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from alert import AlertFilterConfig, AlertManager


def event(sid=45005, priority=2) -> dict:
    return dict(timestamp=1000.0, sid=sid, rev=1, msg="SID suppression",
                src_ip="192.0.2.10", src_port=50000, dst_ip="198.51.100.20", dst_port=80,
                protocol="TCP", application_protocol="HTTP", flow_id="tc05-flow",
                priority=priority, match_information=[{"field": "transport.protocol"}])


def main() -> None:
    if not __debug__:
        raise RuntimeError("Run without -O")
    assertions = scenarios = 0

    def check(condition, message):
        nonlocal assertions
        assert condition, message
        assertions += 1

    policies = (
        ("configured SID", AlertFilterConfig(suppressed_sids={45005}), 45005, 2, "suppressed"),
        ("unlisted SID", AlertFilterConfig(suppressed_sids={45005}), 45006, 2, "created"),
        ("empty suppression", AlertFilterConfig(suppressed_sids=set()), 45005, 2, "created"),
        ("several SIDs first", AlertFilterConfig(suppressed_sids=[45005, 45006, 45007]), 45005, 2, "suppressed"),
        ("several SIDs last", AlertFilterConfig(suppressed_sids=[45005, 45006, 45007]), 45007, 2, "suppressed"),
        ("suppression beats severity", AlertFilterConfig(minimum_severity="CRITICAL", suppressed_sids={45005}), 45005, 4, "suppressed"),
        ("suppression beats empty allowlists", AlertFilterConfig(suppressed_sids={45005}, allowed_src_ips=set(), allowed_protocols=set()), 45005, 1, "suppressed"),
        ("severity without suppression", AlertFilterConfig(minimum_severity="HIGH", suppressed_sids={45005}), 45006, 4, "filtered"),
    )
    for name, config, sid, priority, expected in policies:
        manager = AlertManager(filter_config=config)
        source = event(sid, priority)
        before = deepcopy(source)
        if expected == "created":
            result = manager.process(source)
            check(result.alert.sid == sid and UUID(result.alert.alert_id).version == 4, name)
        else:
            with patch("alert.models.uuid4", side_effect=AssertionError("UUID allocated for blocked SID")):
                result = manager.process(source)
            check(result.alert is None, name)
        check(result.status == expected, (name, result))
        check(source == before, "Source mutated")
        check(result.reason is None if expected == "created" else isinstance(result.reason, str) and bool(result.reason), "Wrong reason contract")
        if expected == "suppressed":
            check(result.reason == f"SID {sid} is suppressed", "Wrong suppression reason")
        scenarios += 1
        print(f"PASS {name}: {expected}")

    sids = [45005, 45005, 45006]
    config = AlertFilterConfig(suppressed_sids=sids)
    check(config.suppressed_sids == frozenset({45005, 45006}), "Duplicate configuration SIDs not collapsed")
    sids.clear()
    check(config.suppressed_sids == frozenset({45005, 45006}), "Configuration aliases caller list")
    try:
        config.suppressed_sids = frozenset()
    except FrozenInstanceError:
        check(True, "Immutable config")
    else:
        raise AssertionError("Config can be reassigned")
    scenarios += 1
    manager = AlertManager(filter_config=config)
    statuses = []
    ids = []
    for sid in (45005, 45008, 45006, 45008):
        result = manager.process(event(sid))
        statuses.append(result.status)
        if result.alert is not None:
            ids.append(result.alert.alert_id)
            check(result.alert.sid == sid and result.alert.count == 1, "State contamination")
    check(statuses == ["suppressed", "created", "suppressed", "created"], "Suppression leaked into later events")
    check(len(ids) == len(set(ids)) == 2, "Allowed events were merged")
    scenarios += 1
    for sid in ("45005", True, 45005.0, None):
        source = event(sid)
        with patch("alert.models.uuid4", side_effect=AssertionError("UUID for invalid SID")):
            result = manager.process(source)
        check(result.status == "rejected" and result.alert is None and "sid" in result.reason, "SID must use Day 1 integer contract")
        scenarios += 1
    source = event()
    source.update(protocol=" tcp ", src_ip=" 192.0.2.10 ")
    result = manager.process(source)
    check(result.status == "suppressed" and result.reason == "SID 45005 is suppressed", "Normalization changed integer SID handling")
    check(source["protocol"] == " tcp " and source["src_ip"] == " 192.0.2.10 ", "Normalization mutated source")
    scenarios += 1
    for value in (None, "45005", 45005, {"sid": 45005}, [True], [False], [0], [-1], [1.5], ["45005"], [None], [[45005]]):
        try:
            AlertFilterConfig(suppressed_sids=value)
        except ValueError as exc:
            check("suppressed_sids" in str(exc), "Unclear suppression config error")
        else:
            raise AssertionError(f"Invalid suppression list accepted: {value}")
        scenarios += 1
    print("PASS immutable/deduplicated config, strict SID validation and recovery after suppressed events")
    print(f"TC05 PASS: {scenarios} scenarios; {assertions} assertions")


if __name__ == "__main__":
    main()
