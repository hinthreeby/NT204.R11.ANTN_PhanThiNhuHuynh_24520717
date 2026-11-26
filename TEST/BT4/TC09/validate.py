"""TC09: repository persistence through real SQLite and public production APIs.

Run: python -B TEST/BT4/TC09/validate.py
Actual console output is mirrored into result.txt next to this script.
All databases and fault-injection objects live in TemporaryDirectory outside ROOT.
"""

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
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


def alert(timestamp=1000.25, **changes):
    values = dict(
        timestamp=timestamp, sid=49009, rev=2, message="TC09 repository alert", severity="HIGH",
        src_ip="192.0.2.10", src_port=53000, dst_ip="198.51.100.20", dst_port=80,
        protocol="TCP", application_protocol="HTTP", flow_id="tc09-flow", priority=2,
        classtype="web-application-attack", first_seen=timestamp, last_seen=timestamp, count=1,
        match_information=({"field": "transport.payload_hex", "start": 0, "end": 2,
                            "matched_hex": "00ff", "option_index": 1},),
    )
    values.update(changes)
    return Alert(**values)


def detection(timestamp=1000.0, **changes):
    values = dict(timestamp=timestamp, sid=49009, rev=1, msg="TC09 aggregate", priority=2,
                  src_ip="192.0.2.10", src_port=53000, dst_ip="198.51.100.20", dst_port=80,
                  protocol="TCP", application_protocol="HTTP", flow_id="tc09-flow",
                  match_information=[{"field": "transport.protocol"}])
    values.update(changes)
    return values


def config(directory):
    return RepositoryConfig(storage_path=str(directory / "storage" / "alerts.db"))


@contextmanager
def raw_database(path):
    connection = sqlite3.connect(str(path))
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def stored_count(path):
    with raw_database(path) as connection:
        return connection.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


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
            self.check(bool(str(error)), message + ": empty diagnostic")
            return error
        except Exception as error:
            self.failed_assertions += 1
            raise AssertionError(f"{message}: expected {kind.__name__}, got {type(error).__name__}") from error
        self.failed_assertions += 1
        raise AssertionError(f"{message}: expected {kind.__name__}, but no exception was raised")

    def run(self, number, name, scenario):
        before = self.assertions
        try:
            with TemporaryDirectory(prefix=f"ids-tc09-s{number:02d}-") as temporary:
                directory = Path(temporary).resolve()
                self.check(not directory.is_relative_to(ROOT.resolve()), "Temporary database must be outside repository")
                scenario(self, directory)
            self.check(not directory.exists(), "Temporary database or open connection leaked")
        except Exception:
            self.failures += 1
            self.emit(f"FAIL S{number:02d} {name} ({self.assertions - before} assertions attempted)")
            self.emit(traceback.format_exc().rstrip())
        else:
            self.emit(f"PASS S{number:02d} {name} ({self.assertions - before} assertions)")


def same_json_types(checks, actual, expected):
    checks.check(type(actual) is type(expected), "Nested metadata value type changed")
    if isinstance(expected, dict):
        checks.equal(set(actual), set(expected), "Nested metadata keys changed")
        for key in expected:
            same_json_types(checks, actual[key], expected[key])
    elif isinstance(expected, (list, tuple)):
        checks.equal(len(actual), len(expected), "Nested metadata length changed")
        for value, original in zip(actual, expected):
            same_json_types(checks, value, original)


def same_alert(checks, actual, expected):
    checks.check(isinstance(actual, Alert), "Repository must return an Alert")
    checks.equal(set(actual.to_dict()), set(FIELDS), "Alert field set changed")
    for field in FIELDS:
        value, original = getattr(actual, field), getattr(expected, field)
        checks.equal(value, original, f"Preserve {field}")
        checks.check(type(value) is type(original), f"Preserve {field} type")
    same_json_types(checks, actual.match_information, expected.match_information)
    checks.equal(json.loads(json.dumps(actual.to_dict(), ensure_ascii=False, allow_nan=False)),
                 expected.to_dict(), "JSON serialization differs after reading")


def round_trip(checks, directory, sources):
    snapshots = deepcopy(sources)
    cfg = config(directory)
    with AlertRepository(cfg) as repository:
        for source in sources:
            repository.insert(source)
        checks.equal(stored_count(cfg.storage_path), len(sources), "Stored row count")
        for source in sources:
            same_alert(checks, repository.get_by_id(source.alert_id), source)
    checks.equal(sources, snapshots, "Repository mutated source Alerts")


def valid_insert(checks, directory):
    source = alert()
    cfg = config(directory)
    checks.check(not Path(cfg.storage_path).parent.exists(), "Config created parent directory")
    with AlertRepository(cfg) as repository:
        checks.check(Path(cfg.storage_path).is_file(), "Repository did not create database")
        checks.equal(repository.insert(source), None, "Insert return contract")
        checks.equal(stored_count(cfg.storage_path), 1, "Insert did not commit")
        same_alert(checks, repository.get_by_id(source.alert_id), source)


def read_by_id(checks, directory):
    source = alert()
    with AlertRepository(config(directory)) as repository:
        repository.insert(source)
        same_alert(checks, repository.get_by_id(source.alert_id), source)
        checks.check(repository.get_by_id("missing-id") is None, "Unknown ID must return None")


def uuid_preservation(checks, directory):
    sources = [alert() for _ in range(8)]
    checks.equal(len({a.alert_id for a in sources}), 8, "Source UUIDs collide")
    for source in sources:
        checks.equal(UUID(source.alert_id).version, 4, "Expected source UUID4")
    round_trip(checks, directory, sources)


def sid_preservation(checks, directory):
    # Day 3 accepts positive Python ints without a 64-bit upper bound.
    round_trip(checks, directory, [alert(sid=sid) for sid in (1, 49009, 2**63 - 1, 2**100 + 1)])


def unicode_message(checks, directory):
    source = alert(message="Cảnh báo đăng nhập – tiếng Việt 🔐 日本語 'quoted'\nDòng thứ hai")
    round_trip(checks, directory, [source])


def metadata_preservation(checks, directory):
    source = alert(match_information=(
        {"field": "payload", "start": 2, "end": 4, "matched_hex": "00ff", "option_index": 3,
         "metadata": {"tags": ["tiếng Việt", 7, True, None], "score": 1.25,
                      "nested": {"enabled": False, "large_integer": 2**90}}},
        {"field": "flow.state", "start": None, "end": None, "matched_hex": None, "option_index": None},
    ))
    round_trip(checks, directory, [source])
    cfg = config(directory)
    with AlertRepository(cfg) as repository:
        detached = repository.get_by_id(source.alert_id)
        detached.match_information[0]["metadata"]["tags"].append("caller edit")
        same_alert(checks, repository.get_by_id(source.alert_id), source)
    with raw_database(cfg.storage_path) as connection:
        raw, kind = connection.execute("SELECT match_information, typeof(match_information) FROM alerts").fetchone()
        checks.equal(kind, "text", "Evidence SQL type")
        checks.equal(json.loads(raw), source.to_dict()["match_information"], "Raw evidence JSON differs")


def close_reopen(checks, directory):
    cfg = config(directory)
    source = alert()
    repository = AlertRepository(cfg)
    try:
        repository.insert(source)
    finally:
        repository.close()
    repository.close()
    checks.raises(RuntimeError, lambda: repository.get_by_id(source.alert_id), "Closed read")
    checks.raises(RuntimeError, lambda: repository.insert(source), "Closed insert")
    checks.raises(RuntimeError, lambda: repository.update(source), "Closed update")
    with AlertRepository(cfg) as reopened:
        same_alert(checks, reopened.get_by_id(source.alert_id), source)


def process_restart(checks, directory):
    cfg = config(directory)
    sources = [alert(1000.0 + i, sid=49009 + i) for i in range(5)]
    with AlertRepository(cfg) as repository:
        for source in sources:
            repository.insert(source)
    # The child interpreter has no access to this process's Alert objects or connection.
    child = (
        "import json,sys\n"
        "from alert import AlertRepository,RepositoryConfig\n"
        "with AlertRepository(RepositoryConfig(storage_path=sys.argv[1])) as repo:\n"
        "    print(json.dumps([repo.get_by_id(k).to_dict() for k in sys.argv[2:]],allow_nan=False))\n"
    )
    completed = subprocess.run(
        [sys.executable, "-B", "-c", child, cfg.storage_path, *[a.alert_id for a in sources]],
        cwd=ROOT, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONIOENCODING="utf-8"),
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    checks.equal(completed.returncode, 0, f"Child restart failed: {completed.stderr}")
    records = json.loads(completed.stdout)
    checks.equal(len(records), 5, "Restart lost rows")
    for record, source in zip(records, sources):
        checks.equal(record, source.to_dict(), "Restart changed stored fields")
        checks.equal(set(record), set(FIELDS), "Restart lost mandatory fields")
    with AlertRepository(cfg) as reopened:
        checks.equal(stored_count(cfg.storage_path), 5, "Child process changed row count")
        for source in sources:
            same_alert(checks, reopened.get_by_id(source.alert_id), source)


def aggregation_update(checks, directory):
    cfg = config(directory)
    manager = AlertManager(aggregation_config=AggregationConfig(enabled=True, window_seconds=60))
    sources = [detection(1000.0), detection(1010.0), detection(1020.0)]
    originals = deepcopy(sources)
    with AlertRepository(cfg) as repository:
        adapter = AlertPersistenceAdapter(manager, repository)
        identifier = None
        for number, source in enumerate(sources, 1):
            result = adapter.process(source)
            checks.equal(result.status, "created" if number == 1 else "aggregated", "Aggregation status")
            if identifier is None:
                identifier = result.alert.alert_id
            checks.equal(result.alert.alert_id, identifier, "Aggregation changed UUID")
            checks.equal(result.alert.count, number, "Aggregation count progression")
            checks.equal(result.alert.first_seen, 1000.0, "Aggregation moved first_seen")
            checks.equal(result.alert.last_seen, source["timestamp"], "Aggregation last_seen")
            same_alert(checks, repository.get_by_id(identifier), result.alert)
            checks.equal(stored_count(cfg.storage_path), 1, "Merge inserted another row")
        repository.update(result.alert)
        repository.update(result.alert)
        checks.equal(repository.get_by_id(identifier).count, 3, "Repeated update incremented count")
        checks.equal(adapter.flush(), (result.group,), "Flush snapshot")
        checks.equal(adapter.flush(), (), "Duplicate flush output")
    checks.equal(sources, originals, "Aggregation/persistence mutated detection input")
    with AlertRepository(cfg) as reopened:
        same_alert(checks, reopened.get_by_id(identifier), result.alert)


def duplicate_id(checks, directory):
    source = alert()
    cfg = config(directory)
    with AlertRepository(cfg) as repository:
        repository.insert(source)
        replacement = alert(alert_id=source.alert_id, message="must not replace", count=2, last_seen=1010.0)
        checks.raises(sqlite3.IntegrityError, lambda: repository.insert(replacement), "Duplicate ID")
        same_alert(checks, repository.get_by_id(source.alert_id), source)
        checks.equal(stored_count(cfg.storage_path), 1, "Duplicate row inserted")
        other = alert()
        repository.insert(other)
        same_alert(checks, repository.get_by_id(other.alert_id), other)


def invalid_path(checks, directory):
    for path in ("", " ", ":memory:", "file:alerts.db", "invalid\x00path.db"):
        checks.raises(ValueError, lambda path=path: RepositoryConfig(storage_path=path), "Invalid path config")
    occupied = directory / "directory-instead-of-file.db"
    occupied.mkdir()
    checks.raises(sqlite3.OperationalError,
                  lambda: AlertRepository(RepositoryConfig(storage_path=str(occupied))), "Directory used as database")
    checks.check(occupied.is_dir(), "Invalid database directory was removed")
    parent = directory / "parent-is-file"
    parent.write_bytes(b"keep this temporary fixture")
    checks.raises(OSError, lambda: AlertRepository(RepositoryConfig(storage_path=str(parent / "alerts.db"))),
                  "Parent is a file")
    checks.equal(parent.read_bytes(), b"keep this temporary fixture", "Existing parent file changed")


def write_failure(checks, directory):
    cfg = config(directory)
    source = alert()
    with AlertRepository(cfg) as repository:
        with raw_database(cfg.storage_path) as connection:
            connection.execute("""CREATE TRIGGER deny_insert BEFORE INSERT ON alerts
                                  BEGIN SELECT RAISE(ABORT, 'TC09 forced write failure'); END""")
        error = checks.raises(sqlite3.IntegrityError, lambda: repository.insert(source), "Actual SQLite write failure")
        checks.check("TC09 forced write failure" in str(error), "Missing SQLite fault diagnostic")
        checks.check(repository.get_by_id(source.alert_id) is None, "Failed write returned a row")
        checks.equal(stored_count(cfg.storage_path), 0, "Failed write changed row count")
        with raw_database(cfg.storage_path) as connection:
            connection.execute("DROP TRIGGER deny_insert")
        repository.insert(source)
        same_alert(checks, repository.get_by_id(source.alert_id), source)


def transaction_rollback(checks, directory):
    cfg = config(directory)
    original, first_insert, second_insert = alert(), alert(), alert()
    changed = alert(alert_id=original.alert_id, message="must roll back", count=4, last_seen=1040.0)
    with AlertRepository(cfg) as repository:
        repository.insert(original)
        with raw_database(cfg.storage_path) as connection:
            connection.executescript("""
                CREATE TABLE rollback_probe (message TEXT);
                CREATE TRIGGER fail_update AFTER UPDATE ON alerts
                BEGIN INSERT INTO rollback_probe VALUES ('must not commit');
                      SELECT RAISE(FAIL, 'TC09 forced transaction failure'); END;
            """)
        checks.raises(sqlite3.IntegrityError,
                      lambda: repository.apply_changes(inserts=(first_insert, second_insert), updates=(changed,)),
                      "Atomic batch failure")
        checks.check(repository.get_by_id(first_insert.alert_id) is None, "First batch insert survived rollback")
        checks.check(repository.get_by_id(second_insert.alert_id) is None, "Second batch insert survived rollback")
        same_alert(checks, repository.get_by_id(original.alert_id), original)
        checks.equal(stored_count(cfg.storage_path), 1, "Batch changed cardinality after rollback")
        with raw_database(cfg.storage_path) as connection:
            checks.equal(connection.execute("SELECT COUNT(*) FROM rollback_probe").fetchone()[0], 0,
                         "Trigger side effect survived rollback")
            connection.execute("DROP TRIGGER fail_update")
        repository.insert(first_insert)
        checks.equal(stored_count(cfg.storage_path), 2, "Connection unusable after rollback")
    with AlertRepository(cfg) as reopened:
        same_alert(checks, reopened.get_by_id(original.alert_id), original)
        checks.check(reopened.get_by_id(second_insert.alert_id) is None, "Later commit resurrected failed insert")
        with raw_database(cfg.storage_path) as connection:
            checks.equal(connection.execute("SELECT COUNT(*) FROM rollback_probe").fetchone()[0], 0,
                         "Later commit persisted failed trigger effect")


def empty_database(checks, directory):
    cfg = config(directory)
    with AlertRepository(cfg) as repository:
        checks.check(repository.get_by_id("missing") is None, "Empty read must return None")
        checks.equal(stored_count(cfg.storage_path), 0, "Empty database contains test rows")
    with AlertRepository(cfg) as reopened:
        checks.check(reopened.get_by_id("missing") is None, "Reopen created fake rows")
        checks.equal(stored_count(cfg.storage_path), 0, "Reopened empty database is not empty")


def input_immutability(checks, directory):
    cfg = config(directory)
    source = alert(match_information=({"field": "payload", "metadata": {"values": [1, 2, 3]}},))
    original = deepcopy(source)
    with AlertRepository(cfg) as repository:
        repository.insert(source)
        checks.equal(source, original, "Insert mutated input")
        result = repository.get_by_id(source.alert_id)
        result.match_information[0]["metadata"]["values"].append(99)
        checks.equal(source, original, "Read result aliases input")
        same_alert(checks, repository.get_by_id(source.alert_id), original)
        replacement = alert(alert_id=source.alert_id, count=2, last_seen=1001.0,
                            match_information=({"field": "updated", "metadata": {"values": [4, 5]}},))
        before_update = deepcopy(replacement)
        repository.update(replacement)
        checks.equal(replacement, before_update, "Update mutated input")
        replacement.match_information[0]["metadata"]["values"].append(88)
        same_alert(checks, repository.get_by_id(source.alert_id), before_update)
        checks.equal(source, original, "Update changed the old input snapshot")


def finalized_groups(checks, directory):
    cfg = config(directory)
    expected = {}
    with AlertRepository(cfg) as repository:
        adapter = AlertPersistenceAdapter(
            AlertManager(aggregation_config=AggregationConfig(enabled=True, window_seconds=60)), repository)
        first = adapter.process(detection())
        merged = adapter.process(detection(1010.0))
        checks.equal(merged.status, "aggregated", "Before-expiry merge status")
        checks.equal(merged.alert.alert_id, first.alert.alert_id, "Before-expiry ID")
        expired = adapter.process(detection(1061.0))
        checks.equal(expired.status, "created", "New window status")
        checks.equal(expired.finalized, (merged.group,), "Expired group lost from output")
        checks.check(expired.alert.alert_id != merged.alert.alert_id, "New window reused ID")
        checks.equal(expired.alert.count, 1, "New window count did not reset")
        late = adapter.process(detection(999.0))
        checks.equal(late.status, "finalized", "Late singleton status")
        checks.equal(late.finalized, (late.group,), "Late group not finalized")
        checks.equal(adapter.flush(), (expired.group,), "Final active group lost at flush")
        checks.equal(adapter.flush(), (), "Flush duplicated groups")
        for summary in (merged.alert, expired.alert, late.alert):
            expected[summary.alert_id] = summary
            same_alert(checks, repository.get_by_id(summary.alert_id), summary)
        checks.equal(stored_count(cfg.storage_path), 3, "Finalized group row count")
        checks.equal(sum(a.count for a in expected.values()), 4, "Accepted event conservation")
    with AlertRepository(cfg) as reopened:
        checks.equal(stored_count(cfg.storage_path), 3, "Reopen lost finalized groups")
        for identifier, summary in expected.items():
            same_alert(checks, reopened.get_by_id(identifier), summary)


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    started = perf_counter()
    with Path(__file__).with_name("result.txt").open("w", encoding="utf-8", newline="\n") as evidence:
        checks = Checks(evidence)
        local = timezone(timedelta(hours=7), name="Asia/Saigon UTC+07:00")
        checks.emit("Command: python -B TEST/BT4/TC09/validate.py")
        checks.emit(f"Working directory: {Path.cwd()}")
        checks.emit(f"Python: {platform.python_version()}; SQLite: {sqlite3.sqlite_version}")
        checks.emit(f"Run time: {datetime.now(local).isoformat(timespec='seconds')}")
        checks.emit("Database policy: temporary directories outside repository; no production database used")
        scenarios = [
            ("Insert a valid Alert", valid_insert),
            ("Read an Alert by ID and handle missing ID", read_by_id),
            ("Multiple independent Alerts", lambda c, d: round_trip(c, d, [alert(1000.0 + i, sid=49009 + i) for i in range(30)])),
            ("Preserve UUID4 identities", uuid_preservation),
            ("Preserve SID including integers beyond 64 bits", sid_preservation),
            ("Preserve all severity levels", lambda c, d: round_trip(c, d, [alert(severity=s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")])),
            ("Preserve source/destination IP and ports", lambda c, d: round_trip(c, d, [alert(src_ip="203.0.113.7", dst_ip="192.0.2.99", src_port=0, dst_port=65535)])),
            ("Preserve transport/application protocols", lambda c, d: round_trip(c, d, [alert(protocol=p, application_protocol=a) for p, a in (("TCP", "HTTP"), ("UDP", "DNS"), ("TCP", "SMTP"), ("UDP", "UNKNOWN"))])),
            ("Preserve epoch timestamps exactly", lambda c, d: round_trip(c, d, [alert(t) for t in (0.0, 1000.125, 1700000000.125, 4294967296.25)])),
            ("Preserve distinct timestamp/first_seen/last_seen", lambda c, d: round_trip(c, d, [alert(1005.25, first_seen=1000.125, last_seen=1040.5, count=4)])),
            ("Preserve positive counts and reject invalid counts", count_preservation),
            ("Preserve Unicode and quoted messages", unicode_message),
            ("Preserve nullable flow_id/priority/classtype", lambda c, d: round_trip(c, d, [alert(flow_id=None, priority=None, classtype=None)])),
            ("Preserve nested metadata and match evidence", metadata_preservation),
            ("Close safely and reopen a database", close_reopen),
            ("Data persists across a new Python process", process_restart),
            ("Persist aggregate count updates without duplicate rows", aggregation_update),
            ("Reject duplicate alert ID without overwrite", duplicate_id),
            ("Reject invalid database paths without destroying fixtures", invalid_path),
            ("Real SQLite write failure and connection recovery", write_failure),
            ("Roll back a multi-write transaction and trigger side effects", transaction_rollback),
            ("Empty database and missing records", empty_database),
            ("Do not mutate insert/update inputs or alias read metadata", input_immutability),
            ("Persist expired, late and flushed finalized groups", finalized_groups),
        ]
        for number, (name, scenario) in enumerate(scenarios, 1):
            checks.run(number, name, scenario)
        exit_code = 1 if checks.failures else 0
        checks.emit(f"Total scenarios: {len(scenarios)}; passed: {len(scenarios) - checks.failures}; failed: {checks.failures}")
        checks.emit(f"Total assertions: {checks.assertions}; passed: {checks.assertions - checks.failed_assertions}; failed: {checks.failed_assertions}")
        checks.emit("Error details: " + ("see FAIL tracebacks above" if checks.failures else "none"))
        checks.emit(f"Elapsed seconds: {perf_counter() - started:.3f}")
        checks.emit(f"TC09 {'FAIL' if exit_code else 'PASS'}")
        checks.emit(f"Exit code: {exit_code}")
        return exit_code


def count_preservation(checks, directory):
    cfg = config(directory)
    sources = [alert(count=n, last_seen=1010.0) for n in (1, 2, 1000, 2**63 - 1)]
    round_trip(checks, directory, sources)
    with AlertRepository(cfg) as repository:
        for count in (0, -1, True, 1.5, 2**63):
            invalid = alert(count=count)
            checks.raises(ValueError, lambda invalid=invalid: repository.insert(invalid), "Invalid count")
            checks.check(repository.get_by_id(invalid.alert_id) is None, "Invalid count persisted")
        checks.equal(stored_count(cfg.storage_path), len(sources), "Rejected counts altered existing rows")


if __name__ == "__main__":
    raise SystemExit(main())
