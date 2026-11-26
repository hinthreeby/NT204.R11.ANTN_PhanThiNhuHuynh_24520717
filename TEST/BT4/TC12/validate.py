"""TC12: exact Top-N SID/classtype/IP rankings over real temporary SQLite.

Run from the repository root: python -B TEST/BT4/TC12/validate.py
All data and helpers belong to this official case; no shared fixture scripts.
"""

from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
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
from report import ReportConfig, ReportFormatter, ReportGenerator


def fixtures():
    """Independent stored groups; category totals deliberately differ from rows."""
    values = (
        (10, "z", "2", 5), (2, "a", "10", 2), (2, "a", "10", 3),
        (30, "z", "2", 1), (40, None, "3", 4), (50, "null", "4", 4),
        (60, "T\u1ea5n c\u00f4ng", "5", 1), (10, "z", "2", 1),
    )
    return [Alert(
        timestamp=1000.0 + i * 10, first_seen=1000.0 + i * 10,
        last_seen=2000.0 if count > 1 else 1000.0 + i * 10,
        sid=sid, rev=1, message=f"TC12 alert {i}", severity="HIGH",
        src_ip=f"192.0.2.{suffix}", src_port=1234,
        dst_ip=f"198.51.100.{suffix}", dst_port=80,
        protocol="TCP", application_protocol="HTTP", flow_id=None,
        classtype=classtype, count=count,
        match_information=({"metadata": {"index": i, "values": [True, None]}},),
    ) for i, (sid, classtype, suffix, count) in enumerate(values)]


def seed(repo, rows=None):
    for alert in fixtures() if rows is None else rows:
        repo.insert(alert)


def generate(repo, top_n=10, **bounds):
    return ReportGenerator(repo, ReportConfig(top_n=top_n)).generate(**bounds)


def rankings(report):
    """Use the public JSON output for classtype Top-N (not a statistics field)."""
    data = json.loads(ReportFormatter().format_json(report))["statistics"]
    return {name: [(r["value"], r["alert_count"], r["total_count"]) for r in data[name]]
            for name in ("top_sids", "top_classtypes", "top_src_ips", "top_dst_ips")}


EXPECTED = {
    "top_sids": [(10, 2, 6), (2, 2, 5), (40, 1, 4), (50, 1, 4), (30, 1, 1), (60, 1, 1)],
    "top_classtypes": [("z", 3, 7), ("a", 2, 5), (None, 1, 4), ("null", 1, 4), ("T\u1ea5n c\u00f4ng", 1, 1)],
    "top_src_ips": [("192.0.2.2", 3, 7), ("192.0.2.10", 2, 5), ("192.0.2.3", 1, 4),
                    ("192.0.2.4", 1, 4), ("192.0.2.5", 1, 1)],
    "top_dst_ips": [("198.51.100.2", 3, 7), ("198.51.100.10", 2, 5), ("198.51.100.3", 1, 4),
                    ("198.51.100.4", 1, 4), ("198.51.100.5", 1, 1)],
}


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
            with TemporaryDirectory(prefix="ids-tc12-") as temporary:
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


def exact_ranking(c, repo, name):
    seed(repo)
    report = generate(repo)
    c.equal(rankings(report)[name], EXPECTED[name], name + " exact values/counts/order")
    c.equal(report.ranking_basis, "total_count", "ranking basis")
    if name != "top_classtypes":
        c.equal([(r.value, r.alert_count, r.total_count) for r in getattr(report.statistics, name)],
                EXPECTED[name], "raw statistics agree with output")


def ties(c, repo):
    sources = fixtures()[:3]
    rows = [replace(a, count=1, sid=sid, classtype=classtype,
                    src_ip=f"192.0.2.{suffix}", dst_ip=f"198.51.100.{suffix}")
            for a, sid, classtype, suffix in zip(sources, (10, 2, 30), (None, "null", "a"), ("2", "10", "3"))]
    seed(repo, reversed(rows))
    report = generate(repo)
    result = rankings(report)
    c.equal([r[0] for r in result["top_sids"]], [2, 10, 30], "numeric SID tie ordering")
    c.equal([r[0] for r in result["top_classtypes"]], [None, "a", "null"], "nullable lexical classtype ties")
    c.equal([r[0] for r in result["top_src_ips"]], ["192.0.2.10", "192.0.2.2", "192.0.2.3"], "lexical source ties")
    c.equal([r[0] for r in result["top_dst_ips"]], ["198.51.100.10", "198.51.100.2", "198.51.100.3"], "lexical destination ties")
    c.equal(rankings(generate(repo, top_n=1))["top_sids"], [(2, 1, 1)], "tie cutoff")
    c.equal(rankings(generate(repo)), result, "tie ordering repeatable")


def custom_n(c, repo, value):
    seed(repo)
    report = generate(repo, top_n=value)
    c.equal(report.config.top_n, value, "configured N")
    for name, actual in rankings(report).items():
        c.equal(actual, EXPECTED[name][:value], name + " exact truncation")
    c.equal((report.statistics.total_alerts, report.statistics.total_count), (8, 21), "N does not truncate totals")


def weighted(c, repo):
    rows = fixtures()
    # A single weighted Alert must outrank several independent count=1 Alerts.
    rows = [replace(rows[0], count=9)] + [replace(a, sid=2, classtype="a", count=1,
        src_ip="192.0.2.10", dst_ip="198.51.100.10") for a in rows[1:]]
    seed(repo, rows)
    result = rankings(generate(repo, top_n=1))
    c.equal(result["top_sids"], [(10, 1, 9)], "weighted SID beats seven groups")
    c.equal(result["top_classtypes"], [("z", 1, 9)], "weighted classtype")
    c.equal(result["top_src_ips"], [("192.0.2.2", 1, 9)], "weighted source")
    c.equal(result["top_dst_ips"], [("198.51.100.2", 1, 9)], "weighted destination")


def empty(c, repo):
    report = generate(repo, top_n=3)
    c.equal(rankings(report), {name: [] for name in EXPECTED}, "all empty rankings")
    c.equal((report.statistics.total_alerts, report.statistics.total_count), (0, 0), "empty totals")


def time_range(c, repo):
    seed(repo)
    report = generate(repo, from_time=1010, to_time=1040)
    result = rankings(report)
    c.equal(result["top_sids"], [(2, 2, 5), (30, 1, 1)], "SID range")
    c.equal(result["top_classtypes"], [("a", 2, 5), ("z", 1, 1)], "classtype range")
    c.equal(result["top_src_ips"], [("192.0.2.10", 2, 5), ("192.0.2.2", 1, 1)], "source range")
    c.equal(result["top_dst_ips"], [("198.51.100.10", 2, 5), ("198.51.100.2", 1, 1)], "destination range")
    c.equal((report.statistics.total_alerts, report.statistics.total_count), (3, 6), "range totals")
    c.equal((report.from_time, report.to_time, report.range_policy), (1010.0, 1040.0, "[from_time, to_time)"), "range policy")


def boundary(c, repo):
    seed(repo)
    report = generate(repo, from_time=1040, to_time=1050)
    c.equal(rankings(report), {
        "top_sids": [(40, 1, 4)], "top_classtypes": [(None, 1, 4)],
        "top_src_ips": [("192.0.2.3", 1, 4)], "top_dst_ips": [("198.51.100.3", 1, 4)],
    }, "start included, end excluded")
    c.equal(rankings(generate(repo, from_time=1500, to_time=2100)),
            {name: [] for name in EXPECTED}, "last_seen does not select groups")
    c.equal(rankings(generate(repo, from_time=1040, to_time=1040)),
            {name: [] for name in EXPECTED}, "equal bounds")


def real_aggregation(c, repo):
    engine = AlertAggregator(AggregationConfig(enabled=True, window_seconds=60))
    sources = fixtures()
    for i in range(3):
        event = replace(sources[i], sid=10, count=1, classtype="z", src_ip="192.0.2.2",
                        dst_ip="198.51.100.2", timestamp=1000.0 + i, first_seen=1000.0 + i,
                        last_seen=1000.0 + i)
        result = engine.process(event)
        c.equal(result.status, "created" if i == 0 else "merged", "real engine status")
        if i == 0:
            repo.insert(result.group.summary)
        else:
            repo.update(result.group.summary)
    seed(repo, [replace(sources[3], sid=2, count=1)])
    report = generate(repo, top_n=1)
    c.equal((report.statistics.total_alerts, report.statistics.total_count), (2, 4), "aggregate totals")
    c.equal(rankings(report)["top_sids"], [(10, 1, 3)], "persisted aggregate wins")


def nullable_unicode(c, repo):
    seed(repo)
    report = generate(repo)
    c.equal(rankings(report)["top_classtypes"], EXPECTED["top_classtypes"], "null versus literal null and Unicode")
    c.equal([(r.value, r.alert_count, r.total_count) for r in report.statistics.classtype_statistics],
            [(None, 1, 4), ("T\u1ea5n c\u00f4ng", 1, 1), ("a", 2, 5), ("null", 1, 4), ("z", 3, 7)], "full classtype statistics")


def insertion_order(c, repo):
    rows = fixtures()
    seed(repo, reversed(rows))
    with AlertRepository(RepositoryConfig(storage_path=str(Path(repo.config.storage_path).with_name("forward.db")))) as forward:
        seed(forward, rows)
        c.equal(generate(repo), generate(forward), "report independent of insertion order")
        c.equal(rankings(generate(repo)), EXPECTED, "exact rank after reverse insert")


def reopened(c, repo):
    seed(repo)
    expected = generate(repo)
    config = repo.config
    repo.close()
    with AlertRepository(config) as other:
        c.equal(generate(other), expected, "report after reopen")
        c.equal(rankings(generate(other)), EXPECTED, "all rankings after reopen")


def unchanged(c, repo):
    seed(repo)
    before = deepcopy(repo.query())
    db_bytes = Path(repo.config.storage_path).read_bytes()
    report = generate(repo)
    snapshot = deepcopy(report)
    formatter = ReportFormatter()
    for _ in range(3):
        c.equal(rankings(generate(repo)), EXPECTED, "repeatable rankings")
        formatter.format_text(report)
        formatter.format_json(report)
    c.equal(report, snapshot, "statistics not mutated by formatting")
    c.equal(repo.query(), before, "all stored fields unchanged")
    c.equal(Path(repo.config.storage_path).read_bytes(), db_bytes, "database bytes unchanged")


def invalid_n(c, repo):
    seed(repo)
    for value in (0, -1, True, 1.5, "3", None):
        try:
            ReportConfig(top_n=value)
        except ValueError:
            c.equal(True, True, f"invalid N {value!r} rejected")
        else:
            c.equal(True, False, f"invalid N {value!r} accepted")
    c.equal(rankings(generate(repo)), EXPECTED, "invalid config did not change storage")


def main():
    started = perf_counter()
    with Path(__file__).with_name("result.txt").open("w", encoding="utf-8") as evidence:
        c = Checks(evidence)
        c.emit("TC12 - Top SID, Classtype and IP Statistics")
        c.emit(f"Run time: {datetime.now(timezone(timedelta(hours=7))).isoformat()}")
        c.emit(f"Python: {platform.python_version()}; SQLite: real temporary databases")
        cases = [
            *[(f"Exact {name}", lambda c, r, name=name: exact_ranking(c, r, name)) for name in EXPECTED],
            ("Deterministic SID/classtype/IP ties and cutoff", ties),
            ("Custom top_n=1", lambda c, r: custom_n(c, r, 1)),
            ("Custom top_n=3", lambda c, r: custom_n(c, r, 3)),
            ("Top-N larger than category cardinality", lambda c, r: custom_n(c, r, 100)),
            ("Rank by Detection Events rather than Alert Objects", weighted),
            ("Empty SQLite report", empty),
            ("Time range affects every ranking", time_range),
            ("Boundary, equal bounds and opening timestamp policy", boundary),
            ("Real aggregation insert/update changes ranking", real_aggregation),
            ("Nullable and Unicode classtypes", nullable_unicode),
            ("Insertion order does not affect ranking", insertion_order),
            ("Rankings after database reopen", reopened),
            ("Repeated report/formatting does not mutate inputs or SQLite", unchanged),
            ("Invalid top_n rejected without storage mutation", invalid_n),
        ]
        for number, (name, action) in enumerate(cases, 1):
            c.run(number, name, action)
        c.emit(f"Scenarios: {len(cases)}; passed: {len(cases) - c.failures}; failed: {c.failures}")
        c.emit(f"Assertions: {c.assertions} (attempted)")
        c.emit("Error details: " + ("see FAIL tracebacks above" if c.failures else "none"))
        c.emit(f"Elapsed seconds: {perf_counter() - started:.3f}")
        c.emit("TC12 " + ("FAIL" if c.failures else "PASS"))
        c.emit(f"Exit code: {int(bool(c.failures))}")
        return int(bool(c.failures))


if __name__ == "__main__":
    raise SystemExit(main())
