"""TC08: real manager integration with explicit expected group lifecycles.

Run: python -B TEST/BT4/TC08/validate.py
The runner mirrors actual console output into the sibling result.txt.
"""

from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
import math
from pathlib import Path
import platform
import sys
from time import perf_counter
import traceback
from uuid import UUID


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from alert import AggregationConfig, AlertFilterConfig, AlertManager


def event(timestamp, **changes):
    source = dict(timestamp=timestamp, sid=48008, rev=1, msg="TC08 payload match",
                  src_ip="192.0.2.10", src_port=53000, dst_ip="198.51.100.20", dst_port=80,
                  protocol="TCP", application_protocol="HTTP", flow_id="tc08-flow",
                  priority=2, classtype="web-application-attack", match_information=[dict(
                      field="transport.payload_hex", start=0, end=2,
                      matched_hex="00ff", option_index=0)])
    source.update(changes)
    return source


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


def metadata(checks, alert, source):
    for field in ("sid", "rev", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                  "application_protocol", "flow_id", "priority", "classtype"):
        checks.equal(getattr(alert, field), source[field], f"Metadata {field}")
    checks.equal(alert.message, source["msg"], "Metadata message")
    checks.equal(alert.severity, {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}[source["priority"]],
                 "Metadata severity")
    checks.equal(list(alert.match_information), source["match_information"], "Metadata evidence")


class Lifecycle:
    """Test oracle uses explicit labels/statuses, never the engine's window logic.

    Keep closed outputs only in the caller/test to assert conservation. The
    engine itself must deliver each final group once and remove it from state.
    """

    def __init__(self, checks, window=60, filters=None):
        self.c = checks
        self.manager = AlertManager(
            aggregation_config=AggregationConfig(enabled=True, window_seconds=window),
            filter_config=filters,
        )
        self.sources = {}
        self.identifiers = {}
        self.views = {}
        self.closed = {}
        self.inputs = []
        self.accepted = 0

    def verify(self, group, label):
        c = self.c
        sources = self.sources[label]
        summary = group.summary
        c.equal(summary.alert_id, self.identifiers[label], f"Stable group ID {label}")
        c.equal(UUID(summary.alert_id).version, 4, "Group UUID4")
        c.equal(summary.count, len(sources), f"Group count {label}")
        c.equal(summary.timestamp, float(sources[0]["timestamp"]), "Summary timestamp")
        c.equal(summary.first_seen, float(sources[0]["timestamp"]), "first_seen")
        c.equal(summary.last_seen, float(max(s["timestamp"] for s in sources)), "last_seen maximum")
        metadata(c, summary, sources[0])
        c.equal(len(group.members), len(sources), "Number of source members")
        c.equal(group.members[0].alert_id, summary.alert_id, "Group ID from opening event")
        c.equal(len({a.alert_id for a in group.members}), len(sources), "Distinct member IDs")
        for member, source in zip(group.members, sources):
            metadata(c, member, source)
            c.equal(UUID(member.alert_id).version, 4, "Member UUID4")
            c.equal(member.count, 1, "Member count")
            for field in ("timestamp", "first_seen", "last_seen"):
                c.equal(getattr(member, field), float(source["timestamp"]), f"Member {field}")
            c.equal((member.sid, member.src_ip, member.dst_ip),
                    (summary.sid, summary.src_ip, summary.dst_ip), "Group key")

    def collect(self, groups, expected_labels):
        c = self.c
        expected_ids = {self.identifiers[label] for label in expected_labels}
        c.equal(len(groups), len(expected_labels), "Finalized group cardinality")
        c.equal({g.summary.alert_id for g in groups}, expected_ids, "Finalized group IDs")
        labels_by_id = {identifier: label for label, identifier in self.identifiers.items()}
        for group in groups:
            label = labels_by_id[group.summary.alert_id]
            c.check(label not in self.closed, f"Group {label} was finalized twice")
            self.verify(group, label)
            c.equal(group, self.views[label], "Finalized snapshot differs from last update")
            self.closed[label] = deepcopy(group)

    def feed(self, timestamp, status, label=None, finalized=(), **changes):
        c = self.c
        source = event(timestamp, **changes)
        before = deepcopy(source)
        self.inputs.append((source, before))
        result = self.manager.process(source)
        c.equal(source, before, "Detection input mutated")
        c.equal(result.status, status, "Result status")
        if status in {"rejected", "filtered", "suppressed"}:
            c.check(result.alert is None, "Blocked event returned an alert")
            c.check(result.group is None, "Blocked event returned a group")
            c.equal(result.finalized, (), "Blocked event finalized state")
            expected_reason = {
                "filtered": "Severity LOW is below minimum HIGH",
                "suppressed": "SID 48999 is suppressed",
            }
            if status == "rejected":
                c.check(isinstance(result.reason, str) and "priority" in result.reason,
                        "Rejected reason must identify invalid priority")
            else:
                c.equal(result.reason, expected_reason[status], "Policy reason")
            return result
        c.check(result.reason is None, "Successful result has an error reason")
        c.check(result.group is not None and result.alert is result.group.summary,
                "Missing group/summary association")
        if status in {"created", "finalized"}:
            c.check(label not in self.identifiers, "Expected a new group label")
            c.check(result.alert.alert_id not in self.identifiers.values(), "New group reused an old UUID")
            self.identifiers[label] = result.alert.alert_id
            self.sources[label] = []
        else:
            c.check(label in self.identifiers and label not in self.closed,
                    "Merge must target an existing open group")
        self.sources[label].append(before)
        self.accepted += 1
        self.verify(result.group, label)
        self.views[label] = deepcopy(result.group)
        self.collect(result.finalized, finalized)
        return result

    def flush(self, expected_labels):
        groups = self.manager.flush()
        self.collect(groups, expected_labels)
        return groups

    def finish(self, expected_open, total_groups):
        self.flush(expected_open)
        self.flush(())
        c = self.c
        c.equal(len(self.closed), total_groups, "Total finalized alerts/groups")
        c.equal(set(self.closed), set(self.identifiers), "An opened group was lost")
        c.equal(sum(g.summary.count for g in self.closed.values()), self.accepted,
                "Accepted event count conservation")
        c.equal(sum(len(g.members) for g in self.closed.values()), self.accepted,
                "Member conservation")
        c.equal(len({a.alert_id for g in self.closed.values() for a in g.members}), self.accepted,
                "Source alert lost or duplicated across groups")
        for source, before in self.inputs:
            c.equal(source, before, "Input changed after subsequent lifecycle operations")


def sequence(checks, steps, expected_open, total_groups, window=60):
    lifecycle = Lifecycle(checks, window)
    for timestamp, status, label, finalized, changes in steps:
        lifecycle.feed(timestamp, status, label, finalized, **changes)
    lifecycle.finish(expected_open, total_groups)
    return lifecycle


def step(timestamp, status, label, finalized=(), **changes):
    return timestamp, status, label, finalized, changes


def many_windows(checks):
    steps = []
    for index in range(10):
        label = f"window-{index}"
        closed = (f"window-{index - 1}",) if index else ()
        steps.extend([step(1000 + index * 61, "created", label, closed),
                      step(1010 + index * 61, "aggregated", label)])
    sequence(checks, steps, ("window-9",), 10)


def finalized_isolation(checks):
    lifecycle = Lifecycle(checks)
    lifecycle.feed(1000, "created", "A")
    opening_update = lifecycle.feed(1010, "aggregated", "A")
    transition = lifecycle.feed(1100, "created", "B", ("A",), flow_id="new-flow", rev=2)
    old = transition.finalized[0]
    before = deepcopy(old)
    lifecycle.feed(1110, "aggregated", "B", flow_id="third-flow", rev=3)
    lifecycle.feed(1200, "created", "C", ("B",))
    checks.equal(old, before, "Finalized group mutated by future processing")
    checks.equal(opening_update.group, before, "Old provisional snapshot changed after finalize")
    try:
        old.summary.count = 999
    except FrozenInstanceError:
        checks.check(True, "Summary scalar fields are frozen")
    else:
        checks.check(False, "Finalized summary count is writable")
    # Evidence dictionaries are mutable by design, but outside edits must not
    # propagate into another returned snapshot or the current live group.
    old.members[0].match_information[0]["field"] = "caller edit"
    checks.equal(opening_update.group, before, "Finalized output aliases an earlier snapshot")
    lifecycle.feed(1201, "aggregated", "C")
    lifecycle.finish(("C",), 3)


def flush_lifecycle(checks):
    lifecycle = Lifecycle(checks)
    lifecycle.feed(1000, "created", "A")
    lifecycle.feed(1001, "created", "B", sid=48009)
    lifecycle.flush(("A", "B"))
    lifecycle.flush(())
    lifecycle.feed(999, "finalized", "late", ("late",))
    lifecycle.feed(2000, "created", "new")
    lifecycle.finish(("new",), 4)


def blocked_state(checks):
    lifecycle = Lifecycle(checks, filters=AlertFilterConfig(
        minimum_severity="HIGH", suppressed_sids={48999}))
    lifecycle.feed(1000, "created", "A")
    lifecycle.feed(10000, "filtered", priority=4)
    lifecycle.feed(20000, "suppressed", sid=48999)
    lifecycle.feed(30000, "rejected", priority=0)
    lifecycle.feed(1060, "aggregated", "A")
    lifecycle.feed(1061, "created", "B", ("A",))
    lifecycle.finish(("B",), 2)


def stress(checks):
    lifecycle = Lifecycle(checks)
    for window in range(500):
        for offset in (0, 30):
            for key in range(3):
                label = f"window-{window}-key-{key}"
                closed = tuple(f"window-{window - 1}-key-{k}" for k in range(3)) \
                    if window and offset == 0 and key == 0 else ()
                index = window * 6 + (3 if offset else 0) + key
                lifecycle.feed(
                    1000 + window * 61 + offset, "created" if offset == 0 else "aggregated",
                    label, closed, sid=48008 + key, flow_id=f"stress-{index}", rev=window % 7 + 1,
                    match_information=[dict(field="transport.payload_hex", start=0, end=2,
                                            matched_hex=index.to_bytes(2, "big").hex(), option_index=0)],
                )
                checks.check(len(lifecycle.identifiers) - len(lifecycle.closed) <= 3,
                             "More than three groups remain unfinalized")
    lifecycle.finish(tuple(f"window-499-key-{k}" for k in range(3)), 1500)
    checks.equal(lifecycle.accepted, 3000, "Stress accepted event total")
    checks.check(all(g.summary.count == 2 for g in lifecycle.closed.values()),
                 "Every stress window/key must contain exactly two events")


def main():
    started = perf_counter()
    with Path(__file__).with_name("result.txt").open("w", encoding="utf-8", newline="\n") as evidence:
        checks = Checks(evidence)
        local = timezone(timedelta(hours=7), name="Asia/Saigon UTC+07:00")
        checks.emit("Command: python -B TEST/BT4/TC08/validate.py")
        checks.emit(f"Working directory: {Path.cwd()}")
        checks.emit(f"Python: {platform.python_version()}")
        checks.emit(f"Run time: {datetime.now(local).isoformat(timespec='seconds')}")
        scenarios = [
            ("Outside window creates a new group", lambda: sequence(checks, [
                step(1000, "created", "A"), step(1061, "created", "B", ("A",))], ("B",), 2)),
            ("Smallest representable timestamp after boundary", lambda: sequence(checks, [
                step(1000, "created", "A"), step(math.nextafter(1060.0, math.inf), "created", "B", ("A",))], ("B",), 2)),
            ("Exact boundary remains inside window", lambda: sequence(checks, [
                step(1000, "created", "A"), step(1060, "aggregated", "A")], ("A",), 1)),
            ("Two consecutive windows with same key", lambda: sequence(checks, [
                step(1000, "created", "A"), step(1030, "aggregated", "A"),
                step(1061, "created", "B", ("A",)), step(1090, "aggregated", "B")], ("B",), 2)),
            ("Ten consecutive windows with same key", lambda: many_windows(checks)),
            ("Fresh UUIDs across successive groups", lambda: sequence(checks, [
                step(1000, "created", "A"), step(1100, "created", "B", ("A",)),
                step(1200, "created", "C", ("B",))], ("C",), 3)),
            ("Count resets and then increments in new group", lambda: sequence(checks, [
                step(1000, "created", "A"), step(1001, "aggregated", "A"), step(1002, "aggregated", "A"),
                step(1061, "created", "B", ("A",)), step(1062, "aggregated", "B")], ("B",), 2)),
            ("New group fractional first_seen and last_seen", lambda: sequence(checks, [
                step(1234.5, "created", "A"), step(1300.25, "created", "B", ("A",)),
                step(1301.5, "aggregated", "B")], ("B",), 2)),
            ("Sparse stream retains every expired group", lambda: sequence(checks, [
                step(0, "created", "A"), step(10000, "created", "B", ("A",)),
                step(50000, "created", "C", ("B",))], ("C",), 3)),
            ("Finalized snapshot stability and evidence isolation", lambda: finalized_isolation(checks)),
            ("Out-of-order input does not reopen expired window", lambda: sequence(checks, [
                step(1000, "created", "A"), step(1040, "aggregated", "A"), step(1020, "aggregated", "A"),
                step(1061, "created", "B", ("A",)), step(1050, "finalized", "late", ("late",)),
                step(1070, "aggregated", "B")], ("B",), 3)),
            ("Input before first_seen becomes finalized singleton", lambda: sequence(checks, [
                step(1000, "created", "A"), step(999, "finalized", "late1", ("late1",)),
                step(998, "finalized", "late2", ("late2",)), step(1010, "aggregated", "A")], ("A",), 3)),
            ("Independent SID/source/destination keys expire separately", lambda: sequence(checks, [
                step(1000, "created", "A"), step(1010, "created", "B", sid=48009),
                step(1020, "created", "C", src_ip="192.0.2.11"),
                step(1030, "created", "D", dst_ip="198.51.100.21"),
                step(1061, "created", "A2", ("A",)), step(1070, "aggregated", "B", sid=48009),
                step(1081, "created", "C2", ("B", "C"), src_ip="192.0.2.11"),
                step(1091, "created", "D2", ("D",), dst_ip="198.51.100.21")], ("A2", "C2", "D2"), 7)),
            ("Small one-second window", lambda: sequence(checks, [
                step(0, "created", "A"), step(1, "aggregated", "A"),
                step(1.25, "created", "B", ("A",))], ("B",), 2, window=1)),
            ("Large 86400-second window", lambda: sequence(checks, [
                step(1000, "created", "A"), step(13345, "aggregated", "A"),
                step(87400, "aggregated", "A"), step(87400.5, "created", "B", ("A",))],
                ("B",), 2, window=86400)),
            ("Flush clears groups once and retains watermark", lambda: flush_lifecycle(checks)),
            ("Mixed reordered events preserve exact counts", lambda: sequence(checks, [
                step(1000, "created", "A"), step(1030, "aggregated", "A"),
                step(1010, "aggregated", "A"), step(1000, "aggregated", "A"),
                step(990, "finalized", "late1", ("late1",)), step(1061, "created", "B", ("A",)),
                step(1020, "finalized", "late2", ("late2",)), step(1061, "aggregated", "B"),
                step(1060, "finalized", "late3", ("late3",)), step(1070, "aggregated", "B")], ("B",), 5)),
            ("Filtering suppression rejection do not advance window", lambda: blocked_state(checks)),
            ("Fixed window does not slide from last_seen", lambda: sequence(checks, [
                step(1000, "created", "A"), step(1059, "aggregated", "A"),
                step(1061, "created", "B", ("A",))], ("B",), 2)),
            ("Stress: 3000 events and 1500 finalized groups", lambda: stress(checks)),
        ]
        for number, (name, scenario) in enumerate(scenarios, 1):
            checks.run(number, name, scenario)
        exit_code = 1 if checks.failures else 0
        checks.emit(f"Total scenarios: {len(scenarios)}; passed: {len(scenarios) - checks.failures}; failed: {checks.failures}")
        checks.emit(f"Total assertions: {checks.assertions}; passed: {checks.assertions - checks.failed_assertions}; failed: {checks.failed_assertions}")
        checks.emit("Error details: " + ("see FAIL tracebacks above" if checks.failures else "none"))
        checks.emit(f"Elapsed seconds: {perf_counter() - started:.3f}")
        checks.emit(f"TC08 {'FAIL' if exit_code else 'PASS'}")
        checks.emit(f"Exit code: {exit_code}")
        return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
