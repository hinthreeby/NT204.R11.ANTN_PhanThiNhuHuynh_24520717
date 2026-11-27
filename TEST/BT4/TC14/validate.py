"""TC14: text/JSON output from reports generated over temporary SQLite.

Run: python -B TEST/BT4/TC14/validate.py
Explicit output-file tests use the external temporary directory. Only sibling
result.txt is written in the repository; no report artifacts are kept there.
"""

from contextlib import redirect_stdout
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
import platform
import re
import sqlite3
import sys
from tempfile import TemporaryDirectory
from time import perf_counter
import traceback

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from alert import Alert, AlertRepository, RepositoryConfig
from report import ReportConfig, ReportFormatter, ReportGenerator


UNICODE_CLASS = 'C\u1ea3nh b\u00e1o "SQL"\nki\u1ec3m tra'
FORMATTER = ReportFormatter()
SECTIONS = {
    "Severity breakdown": "severity_distribution",
    "SID statistics": "sid_statistics",
    "Classtype statistics": "classtype_statistics",
    "Top-2 SID": "top_sids",
    "Top-2 classtype": "top_classtypes",
    "Top-2 source IP": "top_src_ips",
    "Top-2 destination IP": "top_dst_ips",
    "Transport protocol statistics": "transport_protocol_distribution",
    "Application protocol statistics": "application_protocol_distribution",
}
EXPECTED = {
    "severity_distribution": [("CRITICAL", 1, 3), ("HIGH", 1, 5), ("MEDIUM", 1, 1), ("LOW", 1, 2)],
    "sid_statistics": [(2, 1, 3), (10, 2, 7), (30, 1, 1)],
    "classtype_statistics": [(None, 1, 3), (UNICODE_CLASS, 2, 6), ("null", 1, 2)],
    "top_sids": [(10, 2, 7), (2, 1, 3)],
    "top_classtypes": [(UNICODE_CLASS, 2, 6), (None, 1, 3)],
    "top_src_ips": [("192.0.2.1", 2, 7), ("192.0.2.2", 1, 3)],
    "top_dst_ips": [("198.51.100.1", 1, 5), ("198.51.100.2", 2, 5)],
    "transport_protocol_distribution": [("TCP", 3, 8), ("UDP", 1, 3)],
    "application_protocol_distribution": [("DNS", 1, 3), ("HTTP", 1, 5), ("SMTP", 1, 2), ("UNKNOWN", 1, 1)],
}


def fixtures():
    values = (
        (3600.25, 10, "HIGH", 5, UNICODE_CLASS, "1", "1", "TCP", "HTTP"),
        (3660.0, 2, "CRITICAL", 3, None, "2", "2", "UDP", "DNS"),
        (7199.5, 10, "LOW", 2, "null", "1", "2", "TCP", "SMTP"),
        (7200.0, 30, "MEDIUM", 1, UNICODE_CLASS, "3", "3", "TCP", "UNKNOWN"),
    )
    return [Alert(
        timestamp=timestamp, first_seen=timestamp, last_seen=timestamp + count - 1,
        sid=sid, rev=1, message=f"TC14 alert {i}", severity=severity,
        src_ip=f"192.0.2.{src}", src_port=1234, dst_ip=f"198.51.100.{dst}", dst_port=80,
        protocol=protocol, application_protocol=application, flow_id=None,
        classtype=classtype, count=count,
        match_information=({"metadata": {"index": i, "unicode": UNICODE_CLASS}},),
    ) for i, (timestamp, sid, severity, count, classtype, src, dst, protocol, application) in enumerate(values)]


def seed(repo):
    for alert in fixtures():
        repo.insert(alert)


def generate(repo, bucket="hour", **bounds):
    return ReportGenerator(repo, ReportConfig(top_n=2, time_bucket=bucket)).generate(**bounds)


def outputs(repo, bucket="hour", **bounds):
    report = generate(repo, bucket, **bounds)
    return report, FORMATTER.format_text(report), json.loads(FORMATTER.format_json(report))


def sections(text):
    return {part.splitlines()[0]: part.splitlines()[1:]
            for part in text.rstrip("\n").split("\n\n")[1:]}


def text_rows(text, heading):
    lines = sections(text)[heading]
    if lines == ["  (no data)"]:
        return []
    result = []
    for line in lines:
        match = re.fullmatch(r"  (.+): alerts=(\d+), count=(\d+)", line)
        if match is None:
            raise AssertionError(f"Malformed category line: {line!r}")
        result.append((json.loads(match[1]), int(match[2]), int(match[3])))
    return result


def json_rows(data, key):
    return [(r["value"], r["alert_count"], r["total_count"]) for r in data["statistics"][key]]


def human(c, repo):
    seed(repo)
    _, text, _ = outputs(repo)
    c.equal(text.splitlines()[0], "IDS SECURITY REPORT", "title")
    c.equal(text.endswith("\n"), True, "text ends with newline")
    for heading in SECTIONS:
        c.equal(heading in sections(text), True, heading + " section exists")
    c.equal("Alerts per hour (UTC, [start, end))" in sections(text), True, "time section")
    c.equal("Ranking: total_count descending; category ascending on ties" in text, True, "ranking policy")
    c.equal("Counts: alerts = groups; count = Detection Events" in text, True, "distinct metrics explained")


def parse_json(c, repo):
    seed(repo)
    report = generate(repo)
    encoded = FORMATTER.format_json(report)
    data = json.loads(encoded)
    c.equal(type(data), dict, "JSON object")
    c.equal(set(data), {"from_time", "to_time", "config", "statistics", "timezone",
                       "time_field", "range_policy", "ranking_basis", "timestamp_format"}, "complete metadata keys")
    c.equal(set(data["statistics"]), set(EXPECTED) | {"total_alerts", "total_count", "time_series"}, "complete statistics keys")
    c.equal(data["config"], {"top_n": 2, "time_bucket": "hour"}, "configuration")
    for key, expected in EXPECTED.items():
        c.equal(json_rows(data, key), expected, key + " independently expected values")


def period(c, repo):
    seed(repo)
    _, text, data = outputs(repo, from_time=3600, to_time=10800)
    c.equal((data["from_time"], data["to_time"]), (3600.0, 10800.0), "period epoch seconds")
    c.equal((data["timezone"], data["timestamp_format"], data["time_field"], data["range_policy"]),
            ("UTC", "unix_seconds", "timestamp", "[from_time, to_time)"), "time metadata")
    c.equal("Period from: 1970-01-01T01:00:00Z (3600.0 UTC Unix seconds)" in text, True, "text UTC start")
    c.equal("Period to:   1970-01-01T03:00:00Z (10800.0 UTC Unix seconds)" in text, True, "text UTC end")


def totals(c, repo):
    seed(repo)
    _, text, data = outputs(repo)
    c.equal((data["statistics"]["total_alerts"], data["statistics"]["total_count"]), (4, 11), "JSON totals")
    c.equal("Total alerts: 4\nTotal count: 11\n" in text, True, "text separates groups/events")


def category_output(c, repo, headings):
    seed(repo)
    _, text, data = outputs(repo)
    for heading in headings:
        key = SECTIONS[heading]
        c.equal(text_rows(text, heading), EXPECTED[key], heading + " exact text values")
        c.equal(json_rows(data, key), EXPECTED[key], heading + " exact JSON values")


def time_output(c, repo, bucket, expected):
    seed(repo)
    _, text, data = outputs(repo, bucket)
    c.equal([(r["start_time"], r["end_time"], r["alert_count"], r["total_count"])
             for r in data["statistics"]["time_series"]], expected, "JSON time series")
    parsed = []
    for line in sections(text)[f"Alerts per {bucket} (UTC, [start, end))"]:
        match = re.fullmatch(
            r"  \[(.+?) \((\d+) UTC Unix seconds\), (.+?) \((\d+) UTC Unix seconds\)\): alerts=(\d+), count=(\d+)", line)
        if match is None:
            raise AssertionError(f"Malformed bucket line: {line!r}")
        start, end = int(match[2]), int(match[4])
        c.equal(datetime.fromisoformat(match[1].replace("Z", "+00:00")).timestamp(), start, "start ISO matches epoch")
        c.equal(datetime.fromisoformat(match[3].replace("Z", "+00:00")).timestamp(), end, "end ISO matches epoch")
        parsed.append((start, end, int(match[5]), int(match[6])))
    c.equal(parsed, expected, "text time series")


def consistency(c, repo):
    seed(repo)
    _, text, data = outputs(repo)
    for heading, key in SECTIONS.items():
        c.equal(text_rows(text, heading), json_rows(data, key), heading + " text/JSON consistency")
    header = dict(line.split(": ", 1) for line in text.split("\n\n")[0].splitlines()
                  if line.startswith(("Total alerts:", "Total count:")))
    c.equal(int(header["Total alerts"]), data["statistics"]["total_alerts"], "total alerts consistency")
    c.equal(int(header["Total count"]), data["statistics"]["total_count"], "total count consistency")


def empty(c, repo):
    _, text, data = outputs(repo)
    c.equal((data["statistics"]["total_alerts"], data["statistics"]["total_count"]), (0, 0), "empty JSON totals")
    c.equal("Total alerts: 0\nTotal count: 0\n" in text, True, "empty text totals")
    for heading, key in SECTIONS.items():
        expected = [(name, 0, 0) for name in ("CRITICAL", "HIGH", "MEDIUM", "LOW")] if key == "severity_distribution" else []
        c.equal(text_rows(text, heading), expected, "empty text " + key)
        c.equal(json_rows(data, key), expected, "empty JSON " + key)
    c.equal(data["statistics"]["time_series"], [], "empty JSON buckets")
    c.equal(sections(text)["Alerts per hour (UTC, [start, end))"], ["  (no data)"], "empty text buckets")


def unicode_output(c, repo):
    seed(repo)
    report, text, data = outputs(repo)
    encoded = FORMATTER.format_json(report)
    c.equal("C\u1ea3nh b\u00e1o" in encoded and "C\u1ea3nh b\u00e1o" in text, True, "Unicode unescaped")
    c.equal(json_rows(data, "top_classtypes")[0][0], UNICODE_CLASS, "Unicode/newline/quotes JSON round trip")
    c.equal(text_rows(text, "Top-2 classtype")[0][0], UNICODE_CLASS, "Unicode/newline/quotes text round trip")
    values = [r[0] for r in json_rows(data, "classtype_statistics")]
    c.equal(None in values and "null" in values, True, "null differs from string null")


def console(c, repo):
    seed(repo)
    report, text, _ = outputs(repo)
    stream = StringIO()
    FORMATTER.print_text(report, stream)
    c.equal(stream.getvalue(), text, "explicit stream")
    stdout = StringIO()
    with redirect_stdout(stdout):
        FORMATTER.print_text(report)
    c.equal(stdout.getvalue(), text, "current console stdout")


def explicit_files(c, repo):
    seed(repo)
    report, text, data = outputs(repo)
    folder = Path(repo.config.storage_path).parent
    text_path, json_path = folder / "report.txt", folder / "report.json"
    FORMATTER.write_text(report, text_path)
    FORMATTER.write_json(report, str(json_path))
    c.equal(text_path.read_text(encoding="utf-8"), text, "UTF-8 text file")
    c.equal(json.loads(json_path.read_text(encoding="utf-8")), data, "UTF-8 JSON file")
    c.equal("C\u1ea3nh b\u00e1o".encode("utf-8") in text_path.read_bytes(), True, "Unicode text bytes")
    c.equal("C\u1ea3nh b\u00e1o".encode("utf-8") in json_path.read_bytes(), True, "Unicode JSON bytes")
    c.equal(text_path.is_relative_to(ROOT.resolve()), False, "output files outside repository")


def no_implicit_io(c, repo):
    seed(repo)
    folder = Path(repo.config.storage_path).parent
    before = {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()}
    report = generate(repo)
    FORMATTER.format_text(report)
    FORMATTER.format_json(report)
    FORMATTER.to_dict(report)
    FORMATTER.print_text(report, StringIO())
    c.equal({p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()}, before, "no implicit output files or DB writes")


def immutable(c, repo):
    seed(repo)
    before_rows = deepcopy(repo.query())
    report = generate(repo)
    before_report = deepcopy(report)
    original_json = FORMATTER.format_json(report)
    detached = FORMATTER.to_dict(report)
    detached["statistics"]["severity_distribution"][0]["total_count"] = 999
    detached["config"]["top_n"] = 99
    FORMATTER.format_text(report)
    c.equal(report, before_report, "report not mutated")
    c.equal(FORMATTER.format_json(report), original_json, "detached output")
    c.equal(repo.query(), before_rows, "stored fields/evidence unchanged")


def dynamic(c, repo):
    seed(repo)
    old_report, old_text, _ = outputs(repo)
    source = repo.query()[1]
    repo.update(replace(source, count=20, sid=999, severity="LOW",
                        classtype="Dynamic \u0111\u00e3 c\u1eadp nh\u1eadt", src_ip="203.0.113.9", dst_ip="203.0.113.10"))
    _, text, data = outputs(repo)
    c.equal((data["statistics"]["total_alerts"], data["statistics"]["total_count"]), (4, 28), "changed data drives totals")
    c.equal(text != old_text, True, "text responds to stored data")
    c.equal("Total alerts: 4\nTotal count: 28\n" in text, True, "changed text total")
    c.equal(json_rows(data, "top_sids"), [(999, 1, 20), (10, 2, 7)], "changed SID ranks")
    c.equal(json_rows(data, "top_src_ips")[0], ("203.0.113.9", 1, 20), "changed source ranks")
    c.equal(json_rows(data, "top_dst_ips")[0], ("203.0.113.10", 1, 20), "changed destination ranks")
    c.equal(json_rows(data, "top_classtypes")[0], ("Dynamic \u0111\u00e3 c\u1eadp nh\u1eadt", 1, 20), "changed classtype")
    c.equal(text_rows(text, "Severity breakdown"), [("CRITICAL", 0, 0), ("HIGH", 1, 5), ("MEDIUM", 1, 1), ("LOW", 2, 22)], "changed text severity")
    c.equal(old_report.statistics.total_count, 11, "old snapshot stays independent")


def time_range(c, repo):
    seed(repo)
    _, text, data = outputs(repo, from_time=3600, to_time=7200)
    c.equal((data["statistics"]["total_alerts"], data["statistics"]["total_count"]), (3, 10), "filtered metrics")
    c.equal(json_rows(data, "sid_statistics"), [(2, 1, 3), (10, 2, 7)], "exclusive end absent")
    c.equal("Total alerts: 3\nTotal count: 10\n" in text, True, "filtered text metrics")
    c.equal(len(data["statistics"]["time_series"]), 1, "filtered bucket count")
    c.equal(data["to_time"], 7200.0, "period retained even when exclusive")


def unbounded(c, repo):
    seed(repo)
    _, text, data = outputs(repo)
    c.equal((data["from_time"], data["to_time"]), (None, None), "optional JSON bounds")
    c.equal("Period from: unbounded" in text and "Period to:   unbounded" in text, True, "optional text bounds")


def repeated_reopen(c, repo):
    seed(repo)
    report, text, data = outputs(repo)
    c.equal(FORMATTER.format_text(report), text, "repeatable text")
    c.equal(json.loads(FORMATTER.format_json(report)), data, "repeatable JSON")
    config = repo.config
    repo.close()
    with AlertRepository(config) as other:
        reopened, new_text, new_data = outputs(other)
        c.equal(reopened, report, "report after reopen")
        c.equal(new_text, text, "text after reopen")
        c.equal(new_data, data, "JSON after reopen")


def errors(c, repo):
    seed(repo)
    report = generate(repo)
    c.raises(TypeError, lambda: FORMATTER.format_text(None), "invalid text input")
    c.raises(TypeError, lambda: FORMATTER.format_json({}), "invalid JSON input")
    c.raises(ValueError, lambda: FORMATTER.format_json(replace(report, from_time=float("nan"))), "JSON forbids NaN")
    missing = Path(repo.config.storage_path).parent / "missing" / "report.txt"
    c.raises(FileNotFoundError, lambda: FORMATTER.write_text(report, missing), "text I/O errors propagate")
    c.raises(FileNotFoundError, lambda: FORMATTER.write_json(report, missing), "JSON I/O errors propagate")
    c.equal(missing.parent.exists(), False, "no implicit directory creation")


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
            with TemporaryDirectory(prefix="ids-TC14-") as temporary:
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
        c.emit("TC14 - Human-readable and JSON Report Output")
        c.emit(f"Run time: {datetime.now(timezone(timedelta(hours=7))).isoformat()}")
        c.emit(f"Python: {platform.python_version()}; SQLite: {sqlite3.sqlite_version}; real temporary databases")
        for number, (name, action) in enumerate(cases, 1):
            c.run(number, name, action)
        c.emit(f"Scenarios: {len(cases)}; passed: {len(cases) - c.failures}; failed: {c.failures}")
        c.emit(f"Assertions: {c.assertions} (attempted)")
        c.emit("Error details: " + ("see FAIL tracebacks above" if c.failures else "none"))
        c.emit(f"Elapsed seconds: {perf_counter() - started:.3f}")
        c.emit("TC14 " + ("FAIL" if c.failures else "PASS"))
        c.emit(f"Exit code: {int(bool(c.failures))}")
        return int(bool(c.failures))

if __name__ == "__main__":
    raise SystemExit(execute([
        ("Human-readable title, sections and policies", human),
        ("Parseable JSON with complete statistics and exact expected values", parse_json),
        ("Period and normalized UTC timestamps", period),
        ("Separate Total alerts and Total count", totals),
        ("Severity breakdown text and JSON", lambda c, r: category_output(c, r, ["Severity breakdown"])),
        ("SID and classtype full statistics and Top-N", lambda c, r: category_output(c, r,
            ["SID statistics", "Classtype statistics", "Top-2 SID", "Top-2 classtype"])),
        ("Top source and destination IP", lambda c, r: category_output(c, r, ["Top-2 source IP", "Top-2 destination IP"])),
        ("Transport and application protocol statistics", lambda c, r: category_output(c, r,
            ["Transport protocol statistics", "Application protocol statistics"])),
        ("Hour buckets in both outputs with matching ISO/epoch times",
         lambda c, r: time_output(c, r, "hour", [(3600, 7200, 3, 10), (7200, 10800, 1, 1)])),
        ("Minute buckets in both outputs with matching ISO/epoch times",
         lambda c, r: time_output(c, r, "minute", [(3600, 3660, 1, 5), (3660, 3720, 1, 3),
                                                (7140, 7200, 1, 2), (7200, 7260, 1, 1)])),
        ("Text and JSON agree within every statistics section", consistency),
        ("Valid empty text and JSON report", empty),
        ("Unicode, escaped quotes/newline and nullable classtype", unicode_output),
        ("Console and caller-supplied stream", console),
        ("Explicit UTF-8 output files outside repository", explicit_files),
        ("Formatting/printing creates no implicit report files", no_implicit_io),
        ("Report, detached output and stored data immutability", immutable),
        ("Stored data update changes report values and rankings", dynamic),
        ("Time range changes output metrics and buckets", time_range),
        ("Unbounded period in text and JSON", unbounded),
        ("Deterministic output and database reopen", repeated_reopen),
        ("Invalid input and write errors reported explicitly", errors),
    ]))

