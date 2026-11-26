"""Text and JSON presentation of report snapshots, without repository access.

JSON timestamps retain the Repository's UTC Unix seconds, including fractional
seconds. Text adds ISO 8601 UTC labels where the datetime range permits them.
Only explicit write_* calls create files; paths have no default and their parent
directories must already exist. I/O and encoding errors propagate to the caller.
"""

from dataclasses import asdict
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import TextIO

from .generator import Report


def _time_label(value: float | int | None) -> str:
    if value is None:
        return "unbounded"
    try:
        label = datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        # Statistics accept finite epochs outside datetime's year range.
        return f"{value} (UTC Unix seconds)"
    return f"{label} ({value} UTC Unix seconds)"


class ReportFormatter:
    """Render the same immutable report into text, JSON, console or UTF-8 files.

    Both metrics appear in every statistics section. Rankings use total_count
    descending, with ascending category ties (null before strings). Buckets are
    sparse, UTC aligned, and carry the full count of each group's opening time.
    No files are written by formatting or printing. Explicit writes overwrite
    the supplied destination, and never create directories implicitly.
    """

    def to_dict(self, report: Report) -> dict:
        """Return detached JSON-compatible data, preserving all statistics.

        Integer SIDs and nullable classtypes remain typed row values. A null
        classtype is distinct from the literal string "null" in both outputs.
        """
        if not isinstance(report, Report):
            raise TypeError("Expected Report")
        data = asdict(report)
        data["timestamp_format"] = "unix_seconds"
        data["statistics"]["top_classtypes"] = sorted(
            data["statistics"]["classtype_statistics"],
            key=lambda row: (-row["total_count"], row["value"] is not None, row["value"] or ""),
        )[:report.config.top_n]
        return data

    def format_json(self, report: Report) -> str:
        """Return valid indented JSON with Unicode preserved and no file I/O."""
        return json.dumps(self.to_dict(report), ensure_ascii=False, allow_nan=False, indent=2) + "\n"

    def format_text(self, report: Report) -> str:
        """Return human-readable text with explicit time and counting policies."""
        data = self.to_dict(report)
        stats = data["statistics"]
        lines = [
            "IDS SECURITY REPORT",
            f"Period from: {_time_label(data['from_time'])}",
            f"Period to:   {_time_label(data['to_time'])}",
            f"Time field: {data['time_field']}; range: {data['range_policy']}; timezone: {data['timezone']}",
            f"Total alerts: {stats['total_alerts']}",
            f"Total count: {stats['total_count']}",
            f"Ranking: {data['ranking_basis']} descending; category ascending on ties",
            "Counts: alerts = groups; count = Detection Events",
            "Time buckets: full group count at opening timestamp; empty buckets omitted",
        ]
        sections = (
            ("Severity breakdown", "severity_distribution"),
            ("SID statistics", "sid_statistics"),
            ("Classtype statistics", "classtype_statistics"),
            (f"Top-{report.config.top_n} SID", "top_sids"),
            (f"Top-{report.config.top_n} classtype", "top_classtypes"),
            (f"Top-{report.config.top_n} source IP", "top_src_ips"),
            (f"Top-{report.config.top_n} destination IP", "top_dst_ips"),
            ("Transport protocol statistics", "transport_protocol_distribution"),
            ("Application protocol statistics", "application_protocol_distribution"),
        )
        for title, key in sections:
            lines.extend(("", title))
            if not stats[key]:
                lines.append("  (no data)")
            for row in stats[key]:
                value = json.dumps(row["value"], ensure_ascii=False)
                lines.append(f"  {value}: alerts={row['alert_count']}, count={row['total_count']}")
        lines.extend(("", f"Alerts per {report.config.time_bucket} (UTC, [start, end))"))
        if not stats["time_series"]:
            lines.append("  (no data)")
        for row in stats["time_series"]:
            lines.append(
                f"  [{_time_label(row['start_time'])}, {_time_label(row['end_time'])}): "
                f"alerts={row['alert_count']}, count={row['total_count']}"
            )
        return "\n".join(lines) + "\n"

    def print_text(self, report: Report, stream: TextIO | None = None) -> None:
        """Write text to the current stdout, or an explicitly supplied stream."""
        destination = sys.stdout if stream is None else stream
        destination.write(self.format_text(report))

    def write_text(self, report: Report, output_path: str | Path) -> None:
        """Write text to an explicit path as UTF-8; propagate write errors."""
        Path(output_path).write_text(self.format_text(report), encoding="utf-8")

    def write_json(self, report: Report, output_path: str | Path) -> None:
        """Write JSON to an explicit path as UTF-8; propagate write errors."""
        Path(output_path).write_text(self.format_json(report), encoding="utf-8")
