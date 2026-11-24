"""TC07: exercise within-window aggregation through the real AlertManager.

Run: python -B TEST/BT4/TC07/validate.py
Every run overwrites the sibling result.txt with actual console output.
"""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import platform
import sys
from time import perf_counter
import traceback
from uuid import UUID


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from alert import AggregationConfig, AlertFilterConfig, AlertManager


def event(timestamp=1000.0, **changes):
    source = dict(
        timestamp=timestamp, sid=47007, rev=1, msg="TC07 payload match", priority=2,
        classtype="web-application-attack", src_ip="192.0.2.10", src_port=53000,
        dst_ip="198.51.100.20", dst_port=80, protocol="TCP", application_protocol="HTTP",
        flow_id="tc07-flow", match_information=[dict(
            field="transport.payload_hex", start=0, end=2, matched_hex="00ff", option_index=0,
        )],
    )
    source.update(changes)
    return source


def manager(window=60, **kwargs):
    return AlertManager(aggregation_config=AggregationConfig(enabled=True, window_seconds=window),
                        **kwargs)


def group_key(alert):
    return alert.sid, alert.src_ip, alert.dst_ip


def source_key(source):
    return source["sid"], source["src_ip"].strip(), source["dst_ip"].strip()


class Checks:
    def __init__(self, evidence):
        self.evidence = evidence
        self.assertions = 0
        self.failed_assertions = 0
        self.failures = 0

    def emit(self, message):
        print(message, flush=True)
        self.evidence.write(message + "\n")
        self.evidence.flush()

    def check(self, condition, message):
        self.assertions += 1
        if not condition:
            self.failed_assertions += 1
            raise AssertionError(message)

    def equal(self, actual, expected, message):
        self.check(actual == expected, f"{message}: expected {expected!r}, got {actual!r}")

    def run(self, number, name, scenario):
        before = self.assertions
        try:
            scenario()
        except Exception:
            self.failures += 1
            self.emit(f"FAIL S{number:02d} {name} ({self.assertions - before} assertions attempted)")
            self.emit(traceback.format_exc().rstrip())
        else:
            self.emit(f"PASS S{number:02d} {name} ({self.assertions - before} assertions)")


def process(checks, instance, source):
    before = deepcopy(source)
    result = instance.process(source)
    checks.equal(source, before, "Manager mutated Detection Event")
    return result


def verify_metadata(checks, alert, source):
    expected = {field: source[field] for field in (
        "sid", "rev", "src_port", "dst_port", "flow_id", "priority", "classtype",
    )}
    expected.update(
        src_ip=source["src_ip"].strip(), dst_ip=source["dst_ip"].strip(),
        protocol=source["protocol"].strip().upper(),
        application_protocol=source["application_protocol"].strip().upper(),
        message=source["msg"].strip(),
        severity={1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}[source["priority"]],
    )
    for field, value in expected.items():
        checks.equal(getattr(alert, field), value, f"Metadata {field}")
    evidence = tuple(dict(
        field=item["field"].strip(), start=item.get("start"), end=item.get("end"),
        matched_hex=item["matched_hex"].lower() if item.get("matched_hex") is not None else None,
        option_index=item.get("option_index"),
    ) for item in source["match_information"])
    checks.equal(alert.match_information, evidence, "Match evidence")


def verify_member(checks, member, source):
    verify_metadata(checks, member, source)
    checks.equal(UUID(member.alert_id).version, 4, "Member UUID version")
    checks.equal(member.count, 1, "Source member count")
    for field in ("timestamp", "first_seen", "last_seen"):
        checks.equal(getattr(member, field), float(source["timestamp"]), f"Member {field}")


def verify_group(checks, group, sources, identifier, all_members=False):
    checks.check(group is not None, "Missing AlertGroup")
    alert = group.summary
    checks.equal(UUID(alert.alert_id).version, 4, "Group UUID version")
    checks.equal(alert.alert_id, identifier, "Group UUID must remain stable")
    checks.equal(group_key(alert), source_key(sources[0]), "Aggregation key")
    checks.equal(alert.count, len(sources), "Group count")
    checks.equal(alert.timestamp, float(sources[0]["timestamp"]), "Representative timestamp")
    checks.equal(alert.first_seen, float(sources[0]["timestamp"]), "Fixed first_seen")
    checks.equal(alert.last_seen, float(max(s["timestamp"] for s in sources)), "last_seen maximum")
    verify_metadata(checks, alert, sources[0])
    checks.equal(len(group.members), len(sources), "Member count")
    checks.equal(group.members[0].alert_id, identifier, "Opening member owns group ID")
    verify_member(checks, group.members[-1], sources[-1])
    if all_members:
        checks.equal(len({member.alert_id for member in group.members}), len(sources),
                     "Distinct source UUIDs inside group")
        for member, source in zip(group.members, sources):
            checks.equal(group_key(member), source_key(sources[0]), "Member key")
            verify_member(checks, member, source)
    record = alert.to_dict()
    checks.equal(json.loads(json.dumps(record, allow_nan=False)), record, "JSON round trip")


def verify_result(checks, result, sources, identifier):
    checks.equal(result.status, "created" if len(sources) == 1 else "aggregated", "Result status")
    checks.check(result.reason is None, "Successful result has reason")
    checks.check(result.group is not None, "Successful result missing group")
    checks.check(result.alert is result.group.summary, "Alert must reference group summary")
    checks.equal(result.finalized, (), "Within-window input prematurely finalized a group")
    verify_group(checks, result.group, sources, identifier)


def finish(checks, instance, sources, result):
    finalized = instance.flush()
    checks.equal(finalized, (result.group,), "Flush must return exactly the final group")
    verify_group(checks, finalized[0], sources, result.alert.alert_id, all_members=True)
    checks.equal(instance.flush(), (), "Repeated flush must not duplicate output")


def chain(checks, sources, window=60):
    instance = manager(window)
    originals = deepcopy(sources)
    identifier = None
    for index, source in enumerate(sources):
        result = process(checks, instance, source)
        if identifier is None:
            identifier = result.alert.alert_id
        verify_result(checks, result, sources[:index + 1], identifier)
    checks.equal(sources, originals, "Input list/evidence changed")
    finish(checks, instance, sources, result)
    return result


def separate_keys(checks, changes):
    instance = manager()
    sources = [[event()], [event(**changes)]]
    views = [process(checks, instance, items[0]) for items in sources]
    identifiers = [view.alert.alert_id for view in views]
    for view, items in zip(views, sources):
        verify_result(checks, view, items, view.alert.alert_id)
    checks.check(views[0].alert.alert_id != views[1].alert.alert_id, "Independent group IDs collided")
    checks.check(group_key(views[0].alert) != group_key(views[1].alert), "Keys unexpectedly equal")
    old_other = deepcopy(views[1].group)
    for index in range(2):
        sources[index].append(dict(deepcopy(sources[index][0]), timestamp=1010.0))
        views[index] = process(checks, instance, sources[index][-1])
        verify_result(checks, views[index], sources[index], identifiers[index])
        if index == 0:
            checks.equal(old_other.summary.count, 1, "Other group's snapshot changed")
    finalized = instance.flush()
    checks.equal(len(finalized), 2, "Expected two independent groups")
    checks.equal(finalized, tuple(view.group for view in views), "Independent final snapshots")
    for group, items, identifier in zip(finalized, sources, identifiers):
        verify_group(checks, group, items, identifier, all_members=True)
    checks.equal(instance.flush(), (), "Independent groups emitted twice")


def count_progression(checks):
    result = chain(checks, [event(1000 + index) for index in range(12)])
    checks.equal(result.alert.count, 12, "Twelve events must yield count=12")


def first_seen_anchor(checks):
    result = chain(checks, [event(5000), event(5005), event(5030), event(5059), event(5060)])
    checks.equal(result.alert.first_seen, 5000.0, "Anchor drifted with arrivals")
    checks.equal(result.alert.timestamp, 5000.0, "Representative timestamp drifted")


def last_seen_maximum(checks):
    result = chain(checks, [event(1000), event(1040), event(1010), event(1030), event(1040)])
    checks.equal(result.alert.last_seen, 1040.0, "In-window out-of-order input moved last_seen backward")


def stable_uuid(checks):
    result = chain(checks, [event(1000 + index / 2) for index in range(30)])
    checks.equal(result.alert.alert_id, result.group.members[0].alert_id, "Group ID replaced")
    checks.check(result.alert.alert_id != result.group.members[-1].alert_id,
                 "Group incorrectly adopted the last event UUID")


def disabled(checks):
    for config in (None, AggregationConfig(enabled=False, window_seconds=10)):
        instance = AlertManager(aggregation_config=config)
        source = event()
        results = [process(checks, instance, source) for _ in range(2)]
        checks.check(results[0].alert.alert_id != results[1].alert.alert_id,
                     "Disabled aggregation merged identical events")
        for result in results:
            checks.equal(result.status, "created", "Disabled status")
            checks.check(result.reason is None, "Disabled successful reason")
            checks.check(result.group is None, "Disabled mode returned a group")
            checks.equal(result.finalized, (), "Disabled mode returned finalized groups")
            verify_member(checks, result.alert, source)
            checks.equal(group_key(result.alert), source_key(source), "Disabled key")
        checks.equal(instance.flush(), (), "Disabled mode retained state")


def blocked(checks, status):
    policies = {
        "filtered": AlertFilterConfig(minimum_severity="HIGH"),
        "suppressed": AlertFilterConfig(suppressed_sids={47999}),
        "rejected": AlertFilterConfig(),
    }
    changes = {"filtered": {"priority": 4}, "suppressed": {"sid": 47999},
               "rejected": {"priority": 0}}
    reasons = {"filtered": "Severity LOW is below minimum HIGH",
               "suppressed": "SID 47999 is suppressed"}
    instance = manager(filter_config=policies[status])
    first = event()
    opened = process(checks, instance, first)
    verify_result(checks, opened, [first], opened.alert.alert_id)
    denied = process(checks, instance, event(10000, **changes[status]))
    checks.equal(denied.status, status, "Blocked status")
    checks.check(denied.alert is None, "Blocked event created alert")
    checks.check(denied.group is None, "Blocked event created group")
    checks.equal(denied.finalized, (), "Blocked event expired an open group")
    if status in reasons:
        checks.equal(denied.reason, reasons[status], "Blocked reason")
    else:
        checks.check(isinstance(denied.reason, str) and "priority" in denied.reason,
                     "Rejected reason does not identify invalid priority")
    # Far-future denied input must neither advance watermark nor contribute count.
    accepted = event(1010)
    result = process(checks, instance, accepted)
    verify_result(checks, result, [first, accepted], opened.alert.alert_id)
    finish(checks, instance, [first, accepted], result)


def input_isolation(checks):
    instance = manager()
    source = event(src_ip=" 192.0.2.10 ", protocol=" tcp ", application_protocol=" http ",
                   msg="  TC07 payload match  ", flow_id=" source flow unchanged ")
    original = deepcopy(source)
    first = process(checks, instance, source)
    verify_result(checks, first, [original], first.alert.alert_id)
    first.alert.match_information[0]["field"] = "edited output"
    checks.equal(source, original, "Output evidence aliases input")
    source["match_information"][0]["matched_hex"] = "aabb"
    second = event(1001)
    result = process(checks, instance, second)
    verify_result(checks, result, [original, second], first.alert.alert_id)
    checks.equal(result.group.members[0].match_information[0]["matched_hex"], "00ff",
                 "Input edit leaked into state")
    finish(checks, instance, [original, second], result)


def metadata_preservation(checks):
    sources = [event(), event(1001, rev=2, flow_id="another-flow", src_port=54000, dst_port=8080,
                             protocol="UDP", application_protocol="DNS", msg="Changed message",
                             priority=1, classtype="network-scan", match_information=[dict(
                                 field="dns.query", start=2, end=4, matched_hex="ABCD", option_index=2,
                             )]), event(1002, rev=3, flow_id=None, classtype=None,
                                       match_information=[dict(field="flow.state")])]
    result = chain(checks, sources)
    checks.equal([a.flow_id for a in result.group.members], [s["flow_id"] for s in sources],
                 "Lost flow identities")
    checks.equal([a.rev for a in result.group.members], [1, 2, 3], "Lost revisions")


def stress(checks):
    instance = manager()
    histories = {}
    identifiers = {}
    latest = {}
    for index in range(2000):
        source = event(1000 + index / 64, sid=47007 + index % 4, flow_id=f"stress-flow-{index}",
                       match_information=[dict(field="transport.payload_hex", start=0, end=2,
                                               matched_hex=index.to_bytes(2, "big").hex(),
                                               option_index=0)])
        key = source_key(source)
        histories.setdefault(key, []).append(source)
        result = process(checks, instance, source)
        identifiers.setdefault(key, result.alert.alert_id)
        verify_result(checks, result, histories[key], identifiers[key])
        latest[key] = result.group
    finalized = instance.flush()
    checks.equal(len(finalized), 4, "Stress group cardinality")
    checks.equal(len(set(identifiers.values())), 4, "Stress IDs not independent")
    checks.equal(sum(g.summary.count for g in finalized), 2000, "Stress event conservation")
    checks.equal(sum(len(g.members) for g in finalized), 2000, "Stress metadata conservation")
    for group in finalized:
        key = group_key(group.summary)
        checks.equal(group.summary.count, 500, "Stress per-key count")
        checks.equal(group, latest[key], "Stress final snapshot")
        verify_group(checks, group, histories[key], identifiers[key], all_members=True)
    checks.equal(instance.flush(), (), "Stress flush emitted duplicates")


def main():
    started = perf_counter()
    with Path(__file__).with_name("result.txt").open("w", encoding="utf-8", newline="\n") as evidence:
        checks = Checks(evidence)
        local_time = timezone(timedelta(hours=7), name="Asia/Saigon UTC+07:00")
        checks.emit("Command: python -B TEST/BT4/TC07/validate.py")
        checks.emit(f"Working directory: {Path.cwd()}")
        checks.emit(f"Python: {platform.python_version()}")
        checks.emit(f"Run time: {datetime.now(local_time).isoformat(timespec='seconds')}")
        scenarios = [
            ("Two same-key events within window", lambda: chain(checks, [event(), event(1010)])),
            ("Three same-key events", lambda: chain(checks, [event(), event(1010), event(1020)])),
            ("100 consecutive events", lambda: chain(checks, [event(1000 + i / 4) for i in range(100)])),
            ("Identical timestamps", lambda: chain(checks, [event() for _ in range(8)])),
            ("Exact inclusive boundary", lambda: chain(checks, [event(), event(1060)])),
            ("Different SID: independent groups", lambda: separate_keys(checks, {"sid": 47008})),
            ("Different source IP: independent groups", lambda: separate_keys(checks, {"src_ip": "192.0.2.11"})),
            ("Different destination IP: independent groups", lambda: separate_keys(checks, {"dst_ip": "198.51.100.21"})),
            ("Exact count progression", lambda: count_progression(checks)),
            ("Fixed first_seen anchor", lambda: first_seen_anchor(checks)),
            ("last_seen maximum with in-window reordering", lambda: last_seen_maximum(checks)),
            ("Stable group UUID and distinct member UUIDs", lambda: stable_uuid(checks)),
            ("Default and explicit disabled aggregation", lambda: disabled(checks)),
            ("Filtered input excluded from state and watermark", lambda: blocked(checks, "filtered")),
            ("Suppressed input excluded from state and watermark", lambda: blocked(checks, "suppressed")),
            ("Rejected input excluded from state and watermark", lambda: blocked(checks, "rejected")),
            ("Input normalization and evidence isolation", lambda: input_isolation(checks)),
            ("Per-event flow/revision/metadata preservation", lambda: metadata_preservation(checks)),
            ("Custom 2-second window including boundary", lambda: chain(checks, [event(0), event(1), event(2)], window=2)),
            ("Stress: 2000 valid events, 4 keys, 500 members/group", lambda: stress(checks)),
        ]
        for number, (name, scenario) in enumerate(scenarios, 1):
            checks.run(number, name, scenario)
        exit_code = 1 if checks.failures else 0
        checks.emit(f"Total scenarios: {len(scenarios)}; passed: {len(scenarios) - checks.failures}; failed: {checks.failures}")
        checks.emit(f"Total assertions: {checks.assertions}; passed: {checks.assertions - checks.failed_assertions}; failed: {checks.failed_assertions}")
        checks.emit("Error details: " + ("see FAIL tracebacks above" if checks.failures else "none"))
        checks.emit(f"Elapsed seconds: {perf_counter() - started:.3f}")
        checks.emit(f"TC07 {'FAIL' if exit_code else 'PASS'}")
        checks.emit(f"Exit code: {exit_code}")
        return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
