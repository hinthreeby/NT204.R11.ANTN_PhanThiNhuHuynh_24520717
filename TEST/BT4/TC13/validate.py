"""TC13: stored protocol distributions and UTC event-time buckets.

Run: python -B TEST/BT4/TC13/validate.py
Only sibling result.txt is written in the repository. ICMP is unsupported by
the current Alert/SQLite contract; its explicit rejection is a negative test.
"""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import math
from pathlib import Path
import platform
import sqlite3
import sys
from tempfile import TemporaryDirectory
from time import perf_counter
import traceback

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from alert import Alert, AlertRepository, RepositoryConfig, AggregationConfig
from alert.aggregation import AlertAggregator
from report import ReportConfig, ReportGenerator


def fixtures():
    values = (
        (3599.5, "TCP", "HTTP", 1), (3600.0, "UDP", "DNS", 3),
        (3659.999, "TCP", "HTTP", 2), (3660.0, "TCP", "SMTP", 4),
        (7199.75, "UDP", "DNS", 1), (7200.0, "TCP", "UNKNOWN", 5),
        (14400.0, "UDP", "UNKNOWN", 2),
    )
    return [Alert(
        timestamp=timestamp, first_seen=timestamp,
        last_seen=20000.0 if count > 1 else timestamp,
        sid=10001 + i, rev=1, message=f"TC13 alert {i}", severity="HIGH",
        src_ip="192.0.2.1", src_port=1234, dst_ip="198.51.100.1", dst_port=80,
        protocol=protocol, application_protocol=application, flow_id=None,
        classtype=None, count=count,
        match_information=({"metadata": {"index": i, "values": [True, None]}},),
    ) for i, (timestamp, protocol, application, count) in enumerate(values)]


def seed(repo, rows=None):
    for alert in fixtures() if rows is None else rows:
        repo.insert(alert)


def generate(repo, bucket="hour", **bounds):
    return ReportGenerator(repo, ReportConfig(time_bucket=bucket)).generate(**bounds)


def categories(rows):
    return [(r.value, r.alert_count, r.total_count) for r in rows]


def buckets(report):
    return [(r.start_time, r.end_time, r.alert_count, r.total_count)
            for r in report.statistics.time_series]


def transport(c, repo):
    seed(repo)
    report = generate(repo)
    c.equal(categories(report.statistics.transport_protocol_distribution),
            [("TCP", 4, 12), ("UDP", 3, 6)], "TCP and UDP exact counts")
    c.equal((report.statistics.total_alerts, report.statistics.total_count), (7, 18), "both metrics")
    c.equal(sum(r.alert_count for r in report.statistics.transport_protocol_distribution), 7, "groups conserved")
    c.equal(sum(r.total_count for r in report.statistics.transport_protocol_distribution), 18, "events conserved")


def icmp(c, repo):
    seed(repo)
    before = deepcopy(repo.query())
    c.raises(ValueError, lambda: repo.insert(replace(fixtures()[0], protocol="ICMP")), "ICMP not accepted by current contract")
    c.equal(repo.query(), before, "ICMP failure leaves all data unchanged")
    c.equal(categories(generate(repo).statistics.transport_protocol_distribution),
            [("TCP", 4, 12), ("UDP", 3, 6)], "no fabricated ICMP category")


def applications(c, repo):
    seed(repo)
    rows = generate(repo).statistics.application_protocol_distribution
    c.equal(categories(rows), [("DNS", 2, 4), ("HTTP", 2, 3), ("SMTP", 1, 4), ("UNKNOWN", 2, 7)], "all existing applications")
    c.equal(sum(r.alert_count for r in rows), 7, "application group conservation")
    c.equal(sum(r.total_count for r in rows), 18, "application count conservation")


def hour(c, repo):
    seed(repo)
    report = generate(repo)
    c.equal(buckets(report), [(0, 3600, 1, 1), (3600, 7200, 4, 10),
                              (7200, 10800, 1, 5), (14400, 18000, 1, 2)], "multiple hour buckets")
    c.equal(sum(r.alert_count for r in report.statistics.time_series), 7, "bucket group conservation")
    c.equal(sum(r.total_count for r in report.statistics.time_series), 18, "bucket event conservation")


def minute(c, repo):
    seed(repo)
    c.equal(buckets(generate(repo, "minute")),
            [(3540, 3600, 1, 1), (3600, 3660, 2, 5), (3660, 3720, 1, 4),
             (7140, 7200, 1, 1), (7200, 7260, 1, 5), (14400, 14460, 1, 2)],
            "minute boundaries and weights")


def boundary(c, repo, edge, bucket, expected):
    rows = [replace(a, count=1, timestamp=stamp, first_seen=stamp, last_seen=stamp)
            for a, stamp in zip(fixtures(), (math.nextafter(edge, 0), edge, math.nextafter(edge, math.inf)))]
    seed(repo, rows)
    c.equal(buckets(generate(repo, bucket)), expected, "adjacent representable floats around boundary")


def timezone_equivalence(c, repo):
    seed(repo)
    utc = datetime(1970, 1, 1, 1, tzinfo=timezone.utc)
    local = datetime(1970, 1, 1, 8, tzinfo=timezone(timedelta(hours=7)))
    c.equal(utc.timestamp(), local.timestamp(), "same instant across offsets")
    a = generate(repo, from_time=utc.timestamp(), to_time=7200)
    b = generate(repo, from_time=local.timestamp(), to_time=7200)
    c.equal(a, b, "timezone independent range result")
    c.equal((a.timezone, a.time_field, a.range_policy), ("UTC", "timestamp", "[from_time, to_time)"), "explicit UTC time policy")
    c.equal(buckets(a), [(3600, 7200, 4, 10)], "UTC aligned bucket")


def range_case(c, repo):
    seed(repo)
    report = generate(repo, from_time=3600, to_time=7200)
    c.equal((report.statistics.total_alerts, report.statistics.total_count), (4, 10), "start inclusive end exclusive")
    c.equal(categories(report.statistics.transport_protocol_distribution), [("TCP", 2, 6), ("UDP", 2, 4)], "range transport")
    c.equal(categories(report.statistics.application_protocol_distribution), [("DNS", 2, 4), ("HTTP", 1, 2), ("SMTP", 1, 4)], "range applications")
    c.equal(buckets(report), [(3600, 7200, 4, 10)], "only selected groups bucketed")


def opening_time(c, repo):
    seed(repo)
    report = generate(repo, from_time=18000, to_time=21000)
    c.equal((report.statistics.total_alerts, report.statistics.total_count), (0, 0), "last_seen does not select opening time")
    c.equal(buckets(report), [], "no redistribution into member-event times")
    c.equal(buckets(generate(repo))[-1], (14400, 18000, 1, 2), "group weight stays at opening bucket")


def real_aggregation(c, repo):
    engine = AlertAggregator(AggregationConfig(enabled=True, window_seconds=60))
    for i, a in enumerate(fixtures()[:3]):
        stamp = 3599.0 + i
        result = engine.process(replace(a, sid=10001, count=1, timestamp=stamp,
                                        first_seen=stamp, last_seen=stamp,
                                        protocol="TCP", application_protocol="HTTP"))
        c.equal(result.status, "created" if i == 0 else "merged", "real engine result")
        if i == 0:
            repo.insert(result.group.summary)
        else:
            repo.update(result.group.summary)
    report = generate(repo)
    c.equal(categories(report.statistics.transport_protocol_distribution), [("TCP", 1, 3)], "aggregated transport")
    c.equal(categories(report.statistics.application_protocol_distribution), [("HTTP", 1, 3)], "aggregated application")
    c.equal(buckets(report), [(0, 3600, 1, 3)], "whole count at opening despite last_seen in next hour")


def empty(c, repo):
    for bucket in ("hour", "minute"):
        report = generate(repo, bucket)
        c.equal((report.statistics.total_alerts, report.statistics.total_count), (0, 0), "empty totals")
        c.equal(categories(report.statistics.transport_protocol_distribution), [], "empty transport")
        c.equal(categories(report.statistics.application_protocol_distribution), [], "empty application")
        c.equal(buckets(report), [], "empty time series")


def sparse(c, repo):
    seed(repo)
    report = generate(repo, "minute", from_time=0, to_time=10**12)
    c.equal(len(buckets(report)), 6, "no unbounded zero filling")
    c.equal([r[0] for r in buckets(report)], [3540, 3600, 3660, 7140, 7200, 14400], "gaps omitted and ordering")
    c.equal((report.statistics.total_alerts, report.statistics.total_count), (7, 18), "wide range totals")


def zero_epoch(c, repo):
    seed(repo, [replace(fixtures()[0], timestamp=0.0, first_seen=0.0, last_seen=0.0)])
    c.equal(buckets(generate(repo)), [(0, 3600, 1, 1)], "epoch zero hour")
    c.equal(buckets(generate(repo, "minute")), [(0, 60, 1, 1)], "epoch zero minute")


def readonly(c, repo):
    seed(repo)
    before = deepcopy(repo.query())
    db_bytes = Path(repo.config.storage_path).read_bytes()
    expected = generate(repo)
    for _ in range(3):
        c.equal(generate(repo), expected, "repeatable statistics")
    c.equal(repo.query(), before, "stored fields and metadata unchanged")
    c.equal(Path(repo.config.storage_path).read_bytes(), db_bytes, "database bytes unchanged")


def reopen(c, repo):
    seed(repo)
    expected = generate(repo, "minute")
    config = repo.config
    repo.close()
    with AlertRepository(config) as other:
        c.equal(generate(other, "minute"), expected, "protocol and bucket report after reopen")


class Checks:
    def __init__(self, evidence):
        self.evidence = evidence
        self.assertions = self.failures = 0

    def emit(self, message):
        print(message, flush=True)
        self.evidence.write(message + "\n")
        self.evidence.flush()

    def equal(self, actual, expected, label):
        self.assertions += 1
        if actual != expected:
            raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")

    def raises(self, kind, operation, label):
        self.assertions += 1
        try:
            operation()
        except kind as error:
            if not str(error):
                raise AssertionError(f"{label}: missing error diagnostic")
        else:
            raise AssertionError(f"{label}: expected {kind.__name__}")

    def run(self, number, name, action):
        before = self.assertions
        try:
            with TemporaryDirectory(prefix="ids-TC13-") as temporary:
                folder = Path(temporary).resolve()
                self.equal(folder.is_relative_to(ROOT.resolve()), False, "DB outside repository")
                with AlertRepository(RepositoryConfig(storage_path=str(folder / "alerts.db"))) as repo:
                    action(self, repo)
            self.equal(folder.exists(), False, "temporary files cleaned up")
        except Exception:
            self.failures += 1
            self.emit(f"{number:02d}. FAIL {name} ({self.assertions - before} assertions)")
            self.emit(traceback.format_exc().rstrip())
        else:
            self.emit(f"{number:02d}. PASS {name} ({self.assertions - before} assertions)")


def execute(cases):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    started = perf_counter()
    with Path(__file__).with_name("result.txt").open("w", encoding="utf-8") as evidence:
        c = Checks(evidence)
        c.emit("TC13 - Protocol and Time Statistics")
        c.emit(f"Run time: {datetime.now(timezone(timedelta(hours=7))).isoformat()}")
        c.emit(f"Python: {platform.python_version()}; SQLite: {sqlite3.sqlite_version}; real temporary databases")
        for number, (name, action) in enumerate(cases, 1):
            c.run(number, name, action)
        c.emit(f"Scenarios: {len(cases)}; passed: {len(cases) - c.failures}; failed: {c.failures}")
        c.emit(f"Assertions: {c.assertions} (attempted)")
        c.emit("Error details: " + ("see FAIL tracebacks above" if c.failures else "none"))
        c.emit(f"Elapsed seconds: {perf_counter() - started:.3f}")
        c.emit("TC13 " + ("FAIL" if c.failures else "PASS"))
        c.emit(f"Exit code: {int(bool(c.failures))}")
        return int(bool(c.failures))

if __name__ == "__main__":
    raise SystemExit(execute([
        ("TCP/UDP distribution and metric conservation", transport),
        ("ICMP explicitly rejected: unsupported by current storage contract", icmp),
        ("HTTP/DNS/SMTP/UNKNOWN application distribution", applications),
        ("Multiple UTC hour buckets and aggregation weights", hour),
        ("Multiple UTC minute buckets", minute),
        ("Immediately before/on/after hour boundary",
         lambda c, r: boundary(c, r, 3600.0, "hour", [(0, 3600, 1, 1), (3600, 7200, 2, 2)])),
        ("Immediately before/on/after minute boundary",
         lambda c, r: boundary(c, r, 60.0, "minute", [(0, 60, 1, 1), (60, 120, 2, 2)])),
        ("Equivalent UTC and UTC+07 timestamps", timezone_equivalence),
        ("Range boundaries affect protocol and time statistics", range_case),
        ("Use opening timestamp rather than last_seen", opening_time),
        ("Real aggregation across an hour boundary", real_aggregation),
        ("Empty hour and minute reports", empty),
        ("Sparse buckets over a large time range", sparse),
        ("Epoch zero is a valid timestamp", zero_epoch),
        ("Reporting does not mutate SQLite data", readonly),
        ("Statistics survive database reopen", reopen),
    ]))

