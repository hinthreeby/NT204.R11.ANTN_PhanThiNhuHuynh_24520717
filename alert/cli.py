"""Opt-in CLI composition of existing Alert, persistence and Report APIs.

No matching or packet parsing is implemented here. The pipeline delivers its
Detection Event dictionaries through detection_sink. A fresh manager is used
per invocation; the database retains Alert summaries across invocations.
"""

import argparse
from collections import Counter
from contextlib import ExitStack
import json
import math
from pathlib import Path

from .aggregation_config import AggregationConfig
from .filtering import AlertFilterConfig
from .manager import AlertManager
from .models import Alert
from .repository import AlertRepository
from .repository_config import RepositoryConfig
from .repository_integration import AlertPersistenceAdapter
from .severity import SEVERITIES, SeverityConfig
from report import ReportConfig, ReportFormatter, ReportGenerator


def add_alert_arguments(parser: argparse.ArgumentParser) -> None:
    """Register BT4 flags without changing defaults of pre-existing arguments."""
    group = parser.add_argument_group("BT4 Alert and Report (opt-in)")
    group.add_argument("--enable-alerts", action="store_true", help="Process Core Engine detections through Alert Manager")
    group.add_argument("--alert-db", metavar="PATH", help="SQLite storage path; omitted means storage disabled")
    group.add_argument("--alert-console", action="store_true", help="Print concise accepted Alert snapshots with lifecycle status")
    group.add_argument("--alert-min-severity", choices=sorted(SEVERITIES))
    group.add_argument("--suppress-sid", type=int, action="append", default=[], metavar="SID")
    group.add_argument("--allow-src-ip", action="append", metavar="IP")
    group.add_argument("--allow-dst-ip", action="append", metavar="IP")
    group.add_argument("--allow-protocol", action="append", choices=("TCP", "UDP"))
    group.add_argument("--severity-map", action="append", default=[], metavar="PRIORITY=SEVERITY",
                       help="Override a priority mapping; repeated priorities use the last value")
    group.add_argument("--missing-severity", choices=sorted(SEVERITIES))
    group.add_argument("--unmapped-severity", choices=sorted(SEVERITIES))
    group.add_argument("--aggregate-alerts", action="store_true", help="Enable fixed inclusive event-time windows")
    group.add_argument("--aggregation-window", type=int, metavar="SECONDS", help="Positive window size (default: 60)")
    group.add_argument("--report-console", action="store_true")
    group.add_argument("--report-text", metavar="PATH")
    group.add_argument("--report-json", metavar="PATH")
    group.add_argument("--report-top-n", type=int, metavar="N", help="Positive ranking limit (default: 10)")
    group.add_argument("--report-time-bucket", choices=("hour", "minute"))
    group.add_argument("--report-from", type=float, metavar="EPOCH_SECONDS")
    group.add_argument("--report-to", type=float, metavar="EPOCH_SECONDS")
    parser.set_defaults(_bt4_dests=tuple(action.dest for action in group._group_actions))


def _specified(value: object) -> bool:
    return value is not None and value is not False and value != []


def _same_file(left: Path, right: Path) -> bool:
    return left == right or (left.exists() and right.exists() and left.samefile(right))


class AlertCLI:
    """Own one CLI stream's manager/repository and generate reports after flush.

    Configuration and path validation have no filesystem side effects. open()
    attaches the optional repository to ExitStack. Errors propagate: failed
    persistence must never be treated as a successful detection delivery, and
    no report is generated after a processing/flush failure. Existing databases
    are opened normally, never reset. Reports include all stored rows in their
    requested time range, including rows from previous runs.
    """

    @classmethod
    def from_args(cls, parser: argparse.ArgumentParser, args: argparse.Namespace) -> "AlertCLI | None":
        """Validate explicit BT4 options before any outputs or database open."""
        requested = [name for name in args._bt4_dests
                     if name != "enable_alerts" and _specified(getattr(args, name))]
        if not args.enable_alerts:
            if requested:
                parser.error("BT4 options require --enable-alerts")
            return None
        if not args.enable_core_engine:
            parser.error("--enable-alerts requires --enable-core-engine")
        if any(name.startswith("report_") for name in requested) and args.alert_db is None:
            parser.error("Report options require --alert-db")
        try:
            return cls(args)
        except (TypeError, ValueError) as exc:
            parser.error(str(exc))

    def __init__(self, args: argparse.Namespace) -> None:
        severity = SeverityConfig()
        mapping = dict(severity.priority_mapping)
        for entry in args.severity_map:
            priority, separator, value = entry.partition("=")
            if not separator or not priority.isascii() or not priority.isdecimal():
                raise ValueError("--severity-map requires a positive PRIORITY=SEVERITY")
            mapping[int(priority)] = value.strip().upper()
        self.manager = AlertManager(
            SeverityConfig(mapping, args.missing_severity or severity.missing_severity,
                           args.unmapped_severity or severity.unmapped_severity),
            filter_config=AlertFilterConfig(
                minimum_severity=args.alert_min_severity, suppressed_sids=args.suppress_sid,
                allowed_src_ips=args.allow_src_ip, allowed_dst_ips=args.allow_dst_ip,
                allowed_protocols=args.allow_protocol,
            ),
            aggregation_config=AggregationConfig(
                enabled=args.aggregate_alerts,
                window_seconds=60 if args.aggregation_window is None else args.aggregation_window,
            ),
        )
        self.storage = RepositoryConfig(storage_path=args.alert_db) if args.alert_db is not None else None
        self.report_config = ReportConfig(
            top_n=10 if args.report_top_n is None else args.report_top_n,
            time_bucket=args.report_time_bucket or "hour",
        )
        self.start, self.end = args.report_from, args.report_to
        for value in (self.start, self.end):
            if value is not None and (not math.isfinite(value) or value < 0):
                raise ValueError("Report times must be finite non-negative UTC epoch seconds")
        if self.start is not None and self.end is not None and self.start > self.end:
            raise ValueError("--report-from must be <= --report-to")
        self.text_path, self.json_path = args.report_text, args.report_json
        self.console = args.report_console
        self.alert_console = args.alert_console
        self.repository: AlertRepository | None = None
        self.adapter: AlertPersistenceAdapter | None = None
        self.statuses: Counter[str] = Counter()

    def validate_paths(self, inputs: list[str], outputs: list[str]) -> None:
        """Prevent BT4 outputs/SQLite sidecars overwriting inputs or each other."""
        targets = [Path(p).resolve() for p in outputs]
        targets += [Path(p).resolve() for p in (self.text_path, self.json_path) if p is not None]
        database = Path(self.storage.storage_path).resolve() if self.storage else None
        if database is not None:
            targets.append(database)
        protected = [Path(p).resolve() for p in inputs]
        for index, target in enumerate(targets):
            if target.exists() and target.is_dir():
                raise ValueError("CLI outputs must be file paths, not directories")
            if any(_same_file(target, path) for path in protected + targets[:index]):
                raise ValueError("Outputs/database must differ from all inputs and each other")
        if database is not None:
            for suffix in ("-wal", "-shm", "-journal"):
                sidecar = Path(str(database) + suffix)
                if any(_same_file(sidecar, path) for path in protected + targets[:-1]):
                    raise ValueError("SQLite sidecars must differ from input/output files")

    def open(self, stack: ExitStack) -> None:
        """Open optional storage; the caller's stack closes it on any exit."""
        if self.storage is not None:
            self.repository = stack.enter_context(AlertRepository(self.storage))
        self.adapter = AlertPersistenceAdapter(self.manager, self.repository)

    def process(self, detection: dict) -> None:
        """Receive exactly the Detection Event emitted by the existing pipeline."""
        if self.adapter is None:
            raise RuntimeError("Alert CLI is not open")
        result = self.adapter.process(detection)
        self.statuses[result.status] += 1
        if self.alert_console:
            for group in result.finalized:
                if result.alert is None or group.summary.alert_id != result.alert.alert_id:
                    self._print_alert("finalized", group.summary)
            if result.alert is not None:
                self._print_alert(result.status, result.alert)

    @staticmethod
    def _print_alert(status: str, alert: Alert) -> None:
        record = {name: getattr(alert, name) for name in (
            "alert_id", "sid", "severity", "src_ip", "dst_ip", "protocol",
            "first_seen", "last_seen", "count",
        )}
        print("[ALERT] " + json.dumps({"status": status, **record}, ensure_ascii=False, separators=(",", ":")))

    def finish(self) -> None:
        """Persist final groups once and render only explicitly requested outputs."""
        if self.adapter is None:
            raise RuntimeError("Alert CLI is not open")
        finalized = self.adapter.flush()
        if self.alert_console:
            for group in finalized:
                self._print_alert("finalized", group.summary)
        if self.console or self.text_path is not None or self.json_path is not None:
            if self.repository is None:
                raise RuntimeError("Report requires an open repository")
            report = ReportGenerator(self.repository, self.report_config).generate(
                from_time=self.start, to_time=self.end,
            )
            formatter = ReportFormatter()
            for path in (self.text_path, self.json_path):
                if path is not None:
                    Path(path).parent.mkdir(parents=True, exist_ok=True)
            if self.text_path is not None:
                formatter.write_text(report, self.text_path)
            if self.json_path is not None:
                formatter.write_json(report, self.json_path)
            if self.console:
                formatter.print_text(report)
        print("[ALERT] " + ", ".join(f"{name}={self.statuses[name]}" for name in
              ("created", "aggregated", "finalized", "rejected", "filtered", "suppressed")))
