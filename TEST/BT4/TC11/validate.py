"""TC11: severity statistics from real temporary SQLite storage.

Run from the repository root: python -B TEST/BT4/TC11/validate.py
Only this directory's result.txt is written inside the repository.
"""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import platform
import sys
from tempfile import TemporaryDirectory
from time import perf_counter
import traceback

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from alert import Alert, AlertRepository, RepositoryConfig, AggregationConfig
from alert.aggregation import AlertAggregator
from report import ReportGenerator


def fixtures():
    """Eight distinct IDs; repeated rules/IPs must not collapse report rows."""
    pairs = (("CRITICAL", 1), ("HIGH", 5), ("MEDIUM", 2), ("LOW", 1),
             ("CRITICAL", 3), ("HIGH", 4), ("MEDIUM", 1), ("HIGH", 2))
    return [Alert(
        timestamp=1000.0 + i * 10, first_seen=1000.0 + i * 10,
        last_seen=2000.0 if count > 1 else 1000.0 + i * 10,
        sid=10001, rev=1, message=f"TC11 alert {i}", severity=severity,
        src_ip="192.0.2.1", src_port=1234, dst_ip="198.51.100.1", dst_port=80,
        protocol="TCP", application_protocol="HTTP", flow_id=None,
        classtype="tc11", count=count,
        match_information=({"metadata": {"index": i, "values": [True, None]}},),
    ) for i, (severity, count) in enumerate(pairs)]


def seed(repo, rows=None):
    for alert in fixtures() if rows is None else rows:
        repo.insert(alert)


def severity_rows(report):
    return [(r.value, r.alert_count, r.total_count)
            for r in report.statistics.severity_distribution]


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

    def run(self, number, name, action):
        before = self.assertions
        try:
            with TemporaryDirectory(prefix="ids-tc11-") as temporary:
                folder = Path(temporary).resolve()
                self.equal(folder.is_relative_to(ROOT.resolve()), False, "DB outside repository")
                with AlertRepository(RepositoryConfig(storage_path=str(folder / "alerts.db"))) as repo:
                    action(self, repo)
            self.equal(folder.exists(), False, "temporary DB cleaned up")
        except Exception:
            self.failures += 1
            self.emit(f"{number:02d}. FAIL {name} ({self.assertions - before} assertions)")
            self.emit(traceback.format_exc().rstrip())
        else:
            self.emit(f"{number:02d}. PASS {name} ({self.assertions - before} assertions)")


def totals(c, repo):
    seed(repo)
    result = ReportGenerator(repo).generate()
    c.equal(result.statistics.total_alerts, 8, "Alert Objects")
    c.equal(result.statistics.total_count, 19, "Detection Events")
    c.equal(len(repo.query()), 8, "real stored rows")


def severity(c, repo, name, expected):
    seed(repo)
    rows = severity_rows(ReportGenerator(repo).generate())
    c.equal([r[0] for r in rows], ["CRITICAL", "HIGH", "MEDIUM", "LOW"], "severity ordering")
    c.equal(next(r[1:] for r in rows if r[0] == name), expected, name)


def weighted(c, repo):
    seed(repo)
    result = ReportGenerator(repo).generate()
    c.equal(severity_rows(result), [("CRITICAL", 2, 4), ("HIGH", 3, 11),
                                    ("MEDIUM", 2, 3), ("LOW", 1, 1)], "all severities")
    c.equal(sum(r.alert_count for r in result.statistics.severity_distribution), 8, "group conservation")
    c.equal(sum(r.total_count for r in result.statistics.severity_distribution), 19, "event conservation")


def real_aggregation(c, repo):
    engine = AlertAggregator(AggregationConfig(enabled=True, window_seconds=60))
    source = fixtures()[0]
    group_id = None
    for i, timestamp in enumerate((1000.0, 1010.0, 1060.0)):
        event = replace(source, timestamp=timestamp, first_seen=timestamp, last_seen=timestamp)
        # Each event has a new source UUID while the group UUID stays stable.
        event = replace(event, alert_id=fixtures()[0].alert_id)
        result = engine.process(event)
        c.equal(result.status, "created" if i == 0 else "merged", "aggregation status")
        if i == 0:
            group_id = result.group.summary.alert_id
            repo.insert(result.group.summary)
        else:
            repo.update(result.group.summary)
        c.equal(result.group.summary.alert_id, group_id, "stable group UUID")
    persisted = repo.get_by_id(group_id)
    c.equal((persisted.count, persisted.first_seen, persisted.last_seen), (3, 1000.0, 1060.0), "persisted aggregate")
    report = ReportGenerator(repo).generate()
    c.equal((report.statistics.total_alerts, report.statistics.total_count), (1, 3), "aggregate metrics")
    c.equal(severity_rows(report), [("CRITICAL", 1, 3), ("HIGH", 0, 0),
                                  ("MEDIUM", 0, 0), ("LOW", 0, 0)], "aggregated severity")


def empty(c, repo):
    report = ReportGenerator(repo).generate()
    c.equal((report.statistics.total_alerts, report.statistics.total_count), (0, 0), "empty totals")
    c.equal(severity_rows(report), [("CRITICAL", 0, 0), ("HIGH", 0, 0),
                                  ("MEDIUM", 0, 0), ("LOW", 0, 0)], "zero severity rows")
    c.equal(report.statistics.time_series, (), "empty buckets")


def range_case(c, repo, bounds, expected, breakdown):
    seed(repo)
    report = ReportGenerator(repo).generate(**bounds)
    c.equal((report.statistics.total_alerts, report.statistics.total_count), expected, "range totals")
    c.equal(severity_rows(report), breakdown, "range severity")
    c.equal((report.time_field, report.range_policy, report.timezone),
            ("timestamp", "[from_time, to_time)", "UTC"), "time policy")


def duplicate_categories(c, repo):
    rows = fixtures()
    seed(repo, rows)
    c.equal(len({r.alert_id for r in repo.query()}), 8, "distinct stored UUIDs")
    c.equal(len({r.sid for r in rows}), 1, "same SID control")
    c.equal(ReportGenerator(repo).generate().statistics.total_alerts, 8, "no report deduplication")


def large_counts(c, repo):
    value = 2**63 - 1
    seed(repo, [replace(r, count=value) for r in fixtures()[:2]])
    report = ReportGenerator(repo).generate()
    c.equal((report.statistics.total_alerts, report.statistics.total_count), (2, value * 2), "sum beyond SQLite int64")
    c.equal(severity_rows(report)[:2], [("CRITICAL", 1, value), ("HIGH", 1, value)], "exact large counts")


def unchanged(c, repo):
    seed(repo)
    before = deepcopy(repo.query())
    db_before = Path(repo.config.storage_path).read_bytes()
    first = ReportGenerator(repo).generate()
    for _ in range(3):
        c.equal(ReportGenerator(repo).generate(), first, "repeatable report")
    c.equal(repo.query(), before, "all stored fields unchanged")
    c.equal(Path(repo.config.storage_path).read_bytes(), db_before, "database bytes unchanged")


def reopened(c, repo):
    seed(repo)
    expected = ReportGenerator(repo).generate()
    config = repo.config
    repo.close()
    with AlertRepository(config) as reopened_repo:
        c.equal(ReportGenerator(reopened_repo).generate(), expected, "report after reopen")


def main():
    started = perf_counter()
    with Path(__file__).with_name("result.txt").open("w", encoding="utf-8") as evidence:
        c = Checks(evidence)
        c.emit("TC11 - Severity Statistics")
        c.emit(f"Run time: {datetime.now(timezone(timedelta(hours=7))).isoformat()}")
        c.emit(f"Python: {platform.python_version()}; SQLite: real temporary databases")
        cases = [
            ("Total alerts versus total Detection Events", totals),
            *[(f"Severity {name}", lambda c, r, n=name, e=expected: severity(c, r, n, e))
              for name, expected in (("CRITICAL", (2, 4)), ("HIGH", (3, 11)),
                                     ("MEDIUM", (2, 3)), ("LOW", (1, 1)))],
            ("Mixed severities and aggregated count conservation", weighted),
            ("Real aggregation insert/update including window boundary", real_aggregation),
            ("Empty SQLite report", empty),
            ("Time range includes start and excludes end; opening time not last_seen",
             lambda c, r: range_case(c, r, dict(from_time=1010, to_time=1040), (3, 8),
                 [("CRITICAL", 0, 0), ("HIGH", 1, 5), ("MEDIUM", 1, 2), ("LOW", 1, 1)])),
            ("From-time only", lambda c, r: range_case(c, r, dict(from_time=1050), (3, 7),
                 [("CRITICAL", 0, 0), ("HIGH", 2, 6), ("MEDIUM", 1, 1), ("LOW", 0, 0)])),
            ("To-time only", lambda c, r: range_case(c, r, dict(to_time=1020), (2, 6),
                 [("CRITICAL", 1, 1), ("HIGH", 1, 5), ("MEDIUM", 0, 0), ("LOW", 0, 0)])),
            ("Equal bounds give empty report", lambda c, r: range_case(c, r, dict(from_time=1030, to_time=1030), (0, 0),
                 [("CRITICAL", 0, 0), ("HIGH", 0, 0), ("MEDIUM", 0, 0), ("LOW", 0, 0)])),
            ("Outside range gives empty report", lambda c, r: range_case(c, r, dict(from_time=1500, to_time=2100), (0, 0),
                 [("CRITICAL", 0, 0), ("HIGH", 0, 0), ("MEDIUM", 0, 0), ("LOW", 0, 0)])),
            ("Distinct Alerts sharing SID/IP are counted independently", duplicate_categories),
            ("Exact large aggregated count totals", large_counts),
            ("Repeated reporting does not mutate SQLite data", unchanged),
            ("Severity report after database reopen", reopened),
        ]
        for number, (name, action) in enumerate(cases, 1):
            c.run(number, name, action)
        c.emit(f"Scenarios: {len(cases)}; passed: {len(cases) - c.failures}; failed: {c.failures}")
        c.emit(f"Assertions: {c.assertions} (attempted)")
        c.emit("Error details: " + ("see FAIL tracebacks above" if c.failures else "none"))
        c.emit(f"Elapsed seconds: {perf_counter() - started:.3f}")
        c.emit("TC11 " + ("FAIL" if c.failures else "PASS"))
        c.emit(f"Exit code: {int(bool(c.failures))}")
        return int(bool(c.failures))


if __name__ == "__main__":
    raise SystemExit(main())
