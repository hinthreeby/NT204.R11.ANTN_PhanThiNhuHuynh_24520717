"""TC10: exact query results against real, temporary SQLite databases.

Run: python -B TEST/BT4/TC10/validate.py
Only sibling result.txt is written in the repository. No TC09 imports or mocks.
"""

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import math
from pathlib import Path
import platform
import sqlite3
import sys
from tempfile import TemporaryDirectory
from time import perf_counter
import traceback
from uuid import UUID


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from alert import (
    AggregationConfig, Alert, AlertManager, AlertPersistenceAdapter,
    AlertRepository, RepositoryConfig,
)


FIELDS = (
    "alert_id", "timestamp", "sid", "rev", "message", "severity", "src_ip", "src_port",
    "dst_ip", "dst_port", "protocol", "application_protocol", "flow_id", "first_seen",
    "last_seen", "priority", "classtype", "count", "match_information",
)
LABELS = tuple("ABCDEFGHIJ")
# Fixture UUID order deliberately differs from time order; F < G breaks a time tie.
IDS = {label: str(UUID(int=number, version=4)) for label, number in
       zip(LABELS, (90, 80, 70, 60, 50, 20, 30, 40, 10, 1))}
INSERT_ORDER = tuple("JGDAICHBFE")


def fixtures():
    rows = (
        ("A", 1000, "CRITICAL", 10001, "192.0.2.10", "198.51.100.20", 1),
        ("B", 1010, "HIGH", 10002, "192.0.2.10", "198.51.100.21", 3),
        ("C", 1020, "MEDIUM", 10001, "192.0.2.11", "198.51.100.20", 1),
        ("D", 1030, "LOW", 10003, "192.0.2.12", "198.51.100.22", 1),
        ("E", 1040, "HIGH", 10002, "192.0.2.11", "198.51.100.21", 2),
        ("F", 1050, "CRITICAL", 10001, "192.0.2.10", "198.51.100.20", 1),
        ("G", 1050, "HIGH", 10004, "192.0.2.10", "198.51.100.20", 1),
        ("H", 1060, "LOW", 2**100 + 1, "203.0.113.7", "192.0.2.99", 1),
        ("I", 1070, "MEDIUM", 10002, "192.0.2.10", "198.51.100.21", 1),
        ("J", 1080, "HIGH", 10003, "192.0.2.11", "198.51.100.20", 1),
    )
    sources = {}
    for index, (label, timestamp, severity, sid, src, dst, count) in enumerate(rows):
        protocol, application = (("TCP", "HTTP"), ("UDP", "DNS"), ("TCP", "SMTP"))[index % 3]
        sources[label] = Alert(
            alert_id=IDS[label], timestamp=float(timestamp), first_seen=float(timestamp),
            last_seen=float(1090 if label == "B" else 1050 if label == "E" else timestamp),
            sid=sid, rev=index + 1, message=f"TC10 cảnh báo {label}", severity=severity,
            src_ip=src, src_port=50000 + index, dst_ip=dst, dst_port=80 + index,
            protocol=protocol, application_protocol=application, count=count,
            flow_id=None if label == "G" else f"tc10-flow-{label}",
            priority=None if label == "G" else {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}[severity],
            classtype=None if label == "G" else "tc10-fixture",
            match_information=({"field": "payload", "start": 0, "end": 2, "matched_hex": "00ff",
                                "option_index": 0, "metadata": {"label": label, "values": [index, True, None]}},),
        )
    return sources


def configuration(directory):
    return RepositoryConfig(storage_path=str(directory / "queries.db"))


@contextmanager
def raw_database(path):
    connection = sqlite3.connect(str(path))
    try:
        with connection:
            yield connection
    finally:
        connection.close()


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

    def raises(self, kind, operation, message):
        self.assertions += 1
        try:
            operation()
        except kind as error:
            self.check(bool(str(error)), message + ": missing diagnostic")
            return error
        except Exception as error:
            self.failed_assertions += 1
            raise AssertionError(f"{message}: expected {kind.__name__}, got {type(error).__name__}") from error
        self.failed_assertions += 1
        raise AssertionError(f"{message}: expected {kind.__name__}, but no exception was raised")

    def run(self, number, name, scenario):
        before = self.assertions
        try:
            with TemporaryDirectory(prefix=f"ids-tc10-s{number:02d}-") as temporary:
                directory = Path(temporary).resolve()
                self.check(not directory.is_relative_to(ROOT.resolve()), "Database must be outside repository")
                scenario(self, directory)
            self.check(not directory.exists(), "Temporary database/connection cleanup failed")
        except Exception:
            self.failures += 1
            self.emit(f"FAIL S{number:02d} {name} ({self.assertions - before} assertions attempted)")
            self.emit(traceback.format_exc().rstrip())
        else:
            self.emit(f"PASS S{number:02d} {name} ({self.assertions - before} assertions)")


@contextmanager
def dataset(checks, directory):
    sources = fixtures()
    before = deepcopy(sources)
    with AlertRepository(configuration(directory)) as repository:
        for label in INSERT_ORDER:
            repository.insert(sources[label])
        with raw_database(configuration(directory).storage_path) as connection:
            checks.equal(connection.execute("SELECT COUNT(*), SUM(count) FROM alerts").fetchone(),
                         (10, 13), "Fixture cardinality/count")
        yield repository, sources
    checks.equal(sources, before, "Query/serialization mutated fixture Alerts")


def expected_records(checks, repository, sources, labels, **filters):
    before = deepcopy(filters)
    actual = repository.query(**filters)
    checks.equal(filters, before, "Query mutated filter input")
    checks.check(isinstance(actual, list), "Query must return a list")
    expected_ids = [sources[label].alert_id for label in labels]
    checks.equal(len(actual), len(expected_ids), "Exact record count")
    checks.equal([record.alert_id for record in actual], expected_ids, "Exact ordered alert IDs")
    checks.equal(len({record.alert_id for record in actual}), len(actual), "Unexpected duplicate IDs")
    for record, label in zip(actual, labels):
        expected = sources[label]
        checks.check(isinstance(record, Alert), "Query returned a non-Alert")
        checks.equal(set(record.to_dict()), set(FIELDS), "Query lost fields")
        for field in FIELDS:
            value, original = getattr(record, field), getattr(expected, field)
            checks.equal(value, original, f"Query changed {label}.{field}")
            checks.check(type(value) is type(original), f"Query changed {label}.{field} type")
        for field in ("severity", "sid", "src_ip", "dst_ip"):
            if filters.get(field) is not None:
                checks.equal(getattr(record, field), filters[field], f"Filter correctness: {field}")
        if filters.get("from_time") is not None:
            checks.check(record.timestamp >= filters["from_time"], "Record before inclusive lower bound")
        if filters.get("to_time") is not None:
            checks.check(record.timestamp < filters["to_time"], "Record at/after exclusive upper bound")
    return actual


def selection(checks, directory, labels, **filters):
    with dataset(checks, directory) as (repository, sources):
        expected_records(checks, repository, sources, labels, **filters)


def query_all(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        expected_records(checks, repository, sources, LABELS)
        expected_records(checks, repository, sources, LABELS, from_time=None, to_time=None,
                         severity=None, sid=None, src_ip=None, dst_ip=None)


def start_boundary(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        expected_records(checks, repository, sources, "FG", from_time=1050, to_time=1060)
        expected_records(checks, repository, sources, (), from_time=math.nextafter(1050.0, math.inf), to_time=1060)


def end_boundary(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        expected_records(checks, repository, sources, "E", from_time=1040, to_time=1050)
        expected_records(checks, repository, sources, "EFG", from_time=1040,
                         to_time=math.nextafter(1050.0, math.inf))


def outside_range(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        for start, end in ((0, 1000), (1081, 2000), (math.nextafter(1030.0, math.inf), 1040)):
            expected_records(checks, repository, sources, (), from_time=start, to_time=end)


def existing_sid(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        expected_records(checks, repository, sources, "ACF", sid=10001)
        expected_records(checks, repository, sources, "BEI", sid=10002)
        expected_records(checks, repository, sources, "H", sid=2**100 + 1)


def missing_sid(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        expected_records(checks, repository, sources, (), sid=99999)
        expected_records(checks, repository, sources, (), sid=1000)


def both_ips(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        expected_records(checks, repository, sources, "AFG", src_ip="192.0.2.10", dst_ip="198.51.100.20")
        expected_records(checks, repository, sources, "CJ", src_ip="192.0.2.11", dst_ip="198.51.100.20")
        expected_records(checks, repository, sources, (), src_ip="192.0.2.12", dst_ip="198.51.100.21")


def multiple_and(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        filters = dict(from_time=1010, to_time=1080, severity="HIGH", sid=10002, dst_ip="198.51.100.21")
        expected_records(checks, repository, sources, "E", src_ip="192.0.2.11", **filters)
        expected_records(checks, repository, sources, "B", src_ip="192.0.2.10", **filters)
        filters["dst_ip"] = "198.51.100.20"
        expected_records(checks, repository, sources, (), src_ip="192.0.2.10", **filters)


def invalid_range(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        error = checks.raises(ValueError, lambda: repository.query(from_time=1060, to_time=1000), "Reversed time range")
        checks.check("from_time" in str(error), "Range error missing parameter diagnostic")
        expected_records(checks, repository, sources, (), from_time=1040, to_time=1040)
        expected_records(checks, repository, sources, LABELS)


def invalid_timestamp(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        values = (-1, float("nan"), float("inf"), float("-inf"), True, False,
                  "1000", [], {}, datetime(2026, 11, 26, tzinfo=timezone.utc), 10**1000)
        for parameter in ("from_time", "to_time"):
            for value in values:
                error = checks.raises(ValueError, lambda p=parameter, v=value: repository.query(**{p: v}),
                                      f"Invalid {parameter}")
                checks.check(parameter in str(error), "Timestamp error missing parameter")
        expected_records(checks, repository, sources, LABELS)


def invalid_severity(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        for value in ("high", "critical", "UNKNOWN", "", " ", True, 3, [], {}):
            error = checks.raises(ValueError, lambda v=value: repository.query(severity=v), "Invalid severity")
            checks.check("severity" in str(error), "Severity error missing parameter")
        expected_records(checks, repository, sources, LABELS)


def invalid_sid(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        for value in (True, False, 0, -1, 1.5, 10001.0, "10001", [], {}, float("inf")):
            error = checks.raises(ValueError, lambda v=value: repository.query(sid=v), "Invalid SID")
            checks.check("sid" in str(error), "SID error missing parameter")
        expected_records(checks, repository, sources, LABELS)


def logical_snapshot(connection):
    return (
        connection.execute("SELECT * FROM alerts ORDER BY alert_id").fetchall(),
        connection.execute("SELECT type,name,sql FROM sqlite_master ORDER BY type,name").fetchall(),
        connection.execute("PRAGMA user_version").fetchone(),
    )


def injection(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        path = configuration(directory).storage_path
        with raw_database(path) as monitor:
            before = logical_snapshot(monitor)
            for parameter, value in (
                ("from_time", "0 OR 1=1"), ("to_time", "2000; DROP TABLE alerts; --"),
                ("severity", "HIGH' OR 1=1 --"), ("sid", "10001 OR 1=1"),
                ("src_ip", "192.0.2.10' OR '1'='1"), ("dst_ip", "198.51.100.20'; DROP TABLE alerts; --"),
            ):
                checks.raises(ValueError, lambda p=parameter, v=value: repository.query(**{p: v}),
                              f"Injection via {parameter}")
            checks.equal(logical_snapshot(monitor), before, "Injection altered data/schema")
        expected_records(checks, repository, sources, LABELS)


def ip_versions(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        expected_records(checks, repository, sources, "ABFGI", src_ip="192.0.2.10")
        for parameter in ("src_ip", "dst_ip"):
            for value in ("::1", "2001:db8::1", "::ffff:192.0.2.10", "1.2.3", "999.1.1.1",
                          "192.0.2.0/24", " 192.0.2.10 ", 123, True):
                error = checks.raises(ValueError, lambda p=parameter, v=value: repository.query(**{p: v}),
                                      f"Unsupported/noncanonical {parameter}")
                checks.check(parameter in str(error), "IP error missing parameter")
        expected_records(checks, repository, sources, (), src_ip="0.0.0.0")
        expected_records(checks, repository, sources, (), dst_ip="255.255.255.255")


def deterministic_order(checks, directory):
    checks.check(list(INSERT_ORDER) != list(LABELS), "Fixture insertion accidentally sorted")
    checks.check(sorted(IDS, key=IDS.get) != list(LABELS), "Fixture IDs accidentally ordered by time")
    checks.check(INSERT_ORDER.index("G") < INSERT_ORDER.index("F") and IDS["F"] < IDS["G"],
                 "Tie fixture does not distinguish insertion from ID ordering")
    with dataset(checks, directory) as (repository, sources):
        for _ in range(3):
            expected_records(checks, repository, sources, LABELS)
            expected_records(checks, repository, sources, "FG", from_time=1050,
                             to_time=math.nextafter(1050.0, math.inf))


def after_reopen(checks, directory):
    cfg = configuration(directory)
    sources = fixtures()
    with AlertRepository(cfg) as repository:
        for label in INSERT_ORDER:
            repository.insert(sources[label])
        expected_records(checks, repository, sources, "BEG", from_time=1010, to_time=1060, severity="HIGH")
    with AlertRepository(cfg) as reopened:
        expected_records(checks, reopened, sources, LABELS)
        expected_records(checks, reopened, sources, "BEG", from_time=1010, to_time=1060, severity="HIGH")
        expected_records(checks, reopened, sources, "H", sid=2**100 + 1)


def detection(timestamp):
    return dict(timestamp=float(timestamp), sid=60010, rev=1, msg="TC10 actual aggregation", priority=2,
                src_ip="192.0.2.10", src_port=53000, dst_ip="198.51.100.20", dst_port=80,
                protocol="TCP", application_protocol="HTTP", flow_id=None,
                match_information=[{"field": "transport.protocol"}])


def integration_adapter(repository):
    return AlertPersistenceAdapter(
        AlertManager(aggregation_config=AggregationConfig(enabled=True, window_seconds=60)), repository)


def aggregated_query(checks, directory):
    with AlertRepository(configuration(directory)) as repository:
        adapter = integration_adapter(repository)
        originals = [detection(t) for t in (2000, 2010, 2020)]
        before = deepcopy(originals)
        identifier = None
        for index, source in enumerate(originals, 1):
            result = adapter.process(source)
            checks.equal(result.status, "created" if index == 1 else "aggregated", "Aggregate status")
            identifier = identifier or result.alert.alert_id
            checks.equal(result.alert.alert_id, identifier, "Aggregate group ID")
            checks.equal(result.alert.count, index, "Aggregate count progression")
        sources = {"group": result.alert}
        records = expected_records(checks, repository, sources, ("group",), from_time=2000, to_time=2001,
                                   severity="HIGH", sid=60010, src_ip="192.0.2.10", dst_ip="198.51.100.20")
        checks.equal(records[0].count, 3, "Query lost aggregate count")
        checks.equal((records[0].first_seen, records[0].last_seen), (2000.0, 2020.0), "Aggregate time fields")
        expected_records(checks, repository, sources, (), from_time=2010, to_time=2030)
        checks.equal(adapter.flush(), (result.group,), "Aggregate flush")
        expected_records(checks, repository, sources, ("group",))
        checks.equal(originals, before, "Aggregation/query mutated Detection Events")


def finalized_query(checks, directory):
    cfg = configuration(directory)
    with AlertRepository(cfg) as repository:
        adapter = integration_adapter(repository)
        adapter.process(detection(3000))
        old = adapter.process(detection(3010))
        new = adapter.process(detection(3061))
        checks.equal(new.finalized, (old.group,), "Expiration lost old group")
        late = adapter.process(detection(2999))
        checks.equal(late.status, "finalized", "Late singleton status")
        sources = {"late": late.alert, "old": old.alert, "new": new.alert}
        expected_records(checks, repository, sources, ("old",), from_time=3000, to_time=3061, sid=60010)
        expected_records(checks, repository, sources, ("late",), from_time=2999, to_time=3000)
        checks.equal(adapter.flush(), (new.group,), "Final active group lost")
        checks.equal(adapter.flush(), (), "Flush duplicated output")
        records = expected_records(checks, repository, sources, ("late", "old", "new"))
        checks.equal(sum(a.count for a in records), 4, "Finalized event count conservation")
    with AlertRepository(cfg) as reopened:
        expected_records(checks, reopened, sources, ("old",), from_time=3000, to_time=3061)


def empty_database(checks, directory):
    cfg = configuration(directory)
    with AlertRepository(cfg) as repository:
        for filters in ({}, {"from_time": 0, "to_time": 2000}, {"severity": "HIGH"},
                        {"sid": 10001, "src_ip": "192.0.2.10", "dst_ip": "198.51.100.20"}):
            expected_records(checks, repository, {}, (), **filters)
    with AlertRepository(cfg) as reopened:
        expected_records(checks, reopened, {}, ())


def repeated_queries(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        filters = dict(from_time=1010, to_time=1080, severity="HIGH", sid=10002,
                       src_ip="192.0.2.11", dst_ip="198.51.100.21")
        before = deepcopy(filters)
        first = expected_records(checks, repository, sources, "E", **filters)
        first[0].match_information[0]["metadata"]["values"].append("caller edit")
        for _ in range(20):
            actual = expected_records(checks, repository, sources, "E", **filters)
            checks.check(actual is not first, "Repeated query reused result list")
            checks.check(actual[0] is not first[0], "Repeated query reused mutable Alert snapshot")
        checks.equal(filters, before, "Repeated queries changed caller filters")


def no_mutation(checks, directory):
    with dataset(checks, directory) as (repository, sources):
        path = Path(configuration(directory).storage_path)
        with raw_database(path) as monitor:
            before = logical_snapshot(monitor)
            version = monitor.execute("PRAGMA data_version").fetchone()[0]
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            for _ in range(10):
                expected_records(checks, repository, sources, LABELS)
                expected_records(checks, repository, sources, "B", sid=10002, severity="HIGH", src_ip="192.0.2.10")
                expected_records(checks, repository, sources, (), from_time=2000, to_time=3000)
            checks.equal(monitor.execute("PRAGMA data_version").fetchone()[0], version,
                         "Query committed a write visible to another connection")
            checks.equal(logical_snapshot(monitor), before, "Query changed rows/schema/user_version")
            checks.equal(hashlib.sha256(path.read_bytes()).hexdigest(), digest, "Query changed database bytes")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    started = perf_counter()
    with Path(__file__).with_name("result.txt").open("w", encoding="utf-8", newline="\n") as evidence:
        checks = Checks(evidence)
        checks.emit("Command: python -B TEST/BT4/TC10/validate.py")
        checks.emit(f"Working directory: {Path.cwd()}")
        checks.emit(f"Python: {platform.python_version()}; SQLite: {sqlite3.sqlite_version}")
        checks.emit(f"Run time: {datetime.now(timezone(timedelta(hours=7))).isoformat(timespec='seconds')}")
        checks.emit("Policy: alerts.timestamp; [from_time,to_time); AND; timestamp ASC then alert_id ASC")
        checks.emit("Database policy: temporary SQLite outside repository; explicit expected fixture IDs")
        scenarios = [
            ("Query all and all filters omitted/None", query_all),
            ("Query from_time", lambda c, d: selection(c, d, "EFGHIJ", from_time=1040)),
            ("Query to_time", lambda c, d: selection(c, d, "ABCD", to_time=1040)),
            ("Query from/to range", lambda c, d: selection(c, d, "CDEFG", from_time=1020, to_time=1060)),
            ("Inclusive start boundary and next representable float", start_boundary),
            ("Exclusive end boundary and next representable float", end_boundary),
            ("Ranges outside data or inside a timestamp gap", outside_range),
            ("CRITICAL severity", lambda c, d: selection(c, d, "AF", severity="CRITICAL")),
            ("HIGH severity", lambda c, d: selection(c, d, "BEGJ", severity="HIGH")),
            ("MEDIUM severity", lambda c, d: selection(c, d, "CI", severity="MEDIUM")),
            ("LOW severity", lambda c, d: selection(c, d, "DH", severity="LOW")),
            ("Existing SID including integer beyond 64 bits", existing_sid),
            ("Missing SID and exact SID matching", missing_sid),
            ("Source IP", lambda c, d: selection(c, d, "ABFGI", src_ip="192.0.2.10")),
            ("Destination IP", lambda c, d: selection(c, d, "ACFGJ", dst_ip="198.51.100.20")),
            ("Source and destination IP use AND", both_ips),
            ("Time and severity", lambda c, d: selection(c, d, "BEG", from_time=1010, to_time=1060, severity="HIGH")),
            ("Time and SID", lambda c, d: selection(c, d, "CF", from_time=1010, to_time=1060, sid=10001)),
            ("Time and source IP", lambda c, d: selection(c, d, "BFG", from_time=1010, to_time=1060, src_ip="192.0.2.10")),
            ("Time and destination IP", lambda c, d: selection(c, d, "CFG", from_time=1010, to_time=1060, dst_ip="198.51.100.20")),
            ("All six filters with positive and negative AND controls", multiple_and),
            ("Empty result from conflicting valid filters", lambda c, d: selection(c, d, (), from_time=1000, to_time=1040, severity="HIGH", sid=10003)),
            ("Invalid time range and equal empty bounds", invalid_range),
            ("Invalid timestamp types and non-finite values", invalid_timestamp),
            ("Invalid severity", invalid_severity),
            ("Invalid SID types/range", invalid_sid),
            ("SQL injection through every query filter", injection),
            ("IPv4 accepted; IPv6/noncanonical IP rejected", ip_versions),
            ("Deterministic ordering independent of insertion and UUID time order", deterministic_order),
            ("Queries after database reopen", after_reopen),
            ("Query real aggregated Alert and opening timestamp policy", aggregated_query),
            ("Query expired/late/flushed finalized Alert", finalized_query),
            ("Empty database", empty_database),
            ("Repeated query consistency and detached metadata", repeated_queries),
            ("Queries do not mutate rows/schema/database bytes", no_mutation),
        ]
        for number, (name, scenario) in enumerate(scenarios, 1):
            checks.run(number, name, scenario)
        exit_code = 1 if checks.failures else 0
        checks.emit(f"Total scenarios: {len(scenarios)}; passed: {len(scenarios) - checks.failures}; failed: {checks.failures}")
        checks.emit(f"Total assertions: {checks.assertions}; passed: {checks.assertions - checks.failed_assertions}; failed: {checks.failed_assertions}")
        checks.emit("Error details: " + ("see FAIL tracebacks above" if checks.failures else "none"))
        checks.emit(f"Elapsed seconds: {perf_counter() - started:.3f}")
        checks.emit(f"TC10 {'FAIL' if exit_code else 'PASS'}")
        checks.emit(f"Exit code: {exit_code}")
        return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
