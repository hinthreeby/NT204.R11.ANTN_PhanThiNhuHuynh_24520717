"""Pure statistics over stored Alert snapshots; no packet, database or output I/O.

alert_count counts Alert Objects/groups; total_count sums their count fields.
All Top-N lists rank by total_count descending, then category value ascending
(numeric SID, lexical IPv4). Time buckets are UTC epoch-aligned and sparse.
A group's entire count belongs to its opening timestamp, not member times.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from ipaddress import IPv4Address
import math
from typing import Literal

from alert.models import Alert


CategoryValue = str | int | None
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_FIELDS = ("severity", "sid", "classtype", "src_ip", "dst_ip", "protocol", "application_protocol")
_Table = dict[CategoryValue, tuple[int, int]]


@dataclass(frozen=True, slots=True)
class ReportConfig:
    """Configure positive Top-N and UTC hour/minute buckets without side effects."""

    top_n: int = 10
    time_bucket: Literal["hour", "minute"] = "hour"

    def __post_init__(self) -> None:
        if type(self.top_n) is not int or self.top_n < 1:
            raise ValueError("top_n must be a positive integer (not bool)")
        if not isinstance(self.time_bucket, str) or self.time_bucket not in {"hour", "minute"}:
            raise ValueError("time_bucket must be 'hour' or 'minute'")


@dataclass(frozen=True, slots=True)
class CategoryStatistics:
    """One category with both group count and summed Detection Event count.

    A nullable classtype stays value=None, distinct from strings such as 'null'.
    Using rows rather than JSON object keys also keeps SIDs as integers.
    """

    value: CategoryValue
    alert_count: int
    total_count: int


@dataclass(frozen=True, slots=True)
class TimeBucketStatistics:
    """UTC [start_time, end_time) in integer epoch seconds, with both metrics."""

    start_time: int
    end_time: int
    alert_count: int
    total_count: int


@dataclass(frozen=True, slots=True)
class ReportStatistics:
    """Immutable report data; no strings/files are formatted or emitted.

    Severity includes four zero-valued rows for an empty input. Other empty
    distributions, rankings and time series are empty tuples. Only nonempty
    time buckets are present; no potentially unbounded zero filling occurs.
    Category distributions are ordered by value (None first for classtype),
    except severity, which follows CRITICAL/HIGH/MEDIUM/LOW.
    """

    total_alerts: int
    total_count: int
    severity_distribution: tuple[CategoryStatistics, ...]
    sid_statistics: tuple[CategoryStatistics, ...]
    classtype_statistics: tuple[CategoryStatistics, ...]
    top_sids: tuple[CategoryStatistics, ...]
    top_src_ips: tuple[CategoryStatistics, ...]
    top_dst_ips: tuple[CategoryStatistics, ...]
    transport_protocol_distribution: tuple[CategoryStatistics, ...]
    application_protocol_distribution: tuple[CategoryStatistics, ...]
    time_series: tuple[TimeBucketStatistics, ...]


def _category_key(value: CategoryValue) -> tuple[int, int | str]:
    if value is None:
        return 0, ""
    if type(value) is int:
        return 1, value
    return 2, value


def _rows(table: _Table, values: Iterable[CategoryValue] | None = None) -> tuple[CategoryStatistics, ...]:
    ordered = sorted(table, key=_category_key) if values is None else values
    return tuple(CategoryStatistics(value, *table.get(value, (0, 0))) for value in ordered)


def _top(table: _Table, top_n: int) -> tuple[CategoryStatistics, ...]:
    return tuple(sorted(_rows(table), key=lambda row: (-row.total_count, _category_key(row.value)))[:top_n])


def _timestamp(alert: Alert) -> float:
    """Check the fields used in statistics without modifying a source Alert."""
    if not isinstance(alert, Alert):
        raise TypeError("Statistics require Alert snapshots, not Detection Events")
    if type(alert.count) is not int or alert.count < 1:
        raise ValueError("Alert count must be a positive integer (not bool)")
    if type(alert.sid) is not int or alert.sid < 1:
        raise ValueError("Alert sid must be a positive integer")
    if not isinstance(alert.severity, str) or alert.severity not in _SEVERITIES:
        raise ValueError("Invalid Alert severity")
    if alert.classtype is not None and (not isinstance(alert.classtype, str) or not alert.classtype.strip()):
        raise ValueError("Alert classtype must be a non-empty string or None")
    for field in ("src_ip", "dst_ip"):
        value = getattr(alert, field)
        if not isinstance(value, str) or str(IPv4Address(value)) != value:
            raise ValueError(f"Alert {field} must be normalized IPv4")
    if (not isinstance(alert.protocol, str) or alert.protocol not in {"TCP", "UDP"}
            or not isinstance(alert.application_protocol, str)
            or alert.application_protocol not in {"HTTP", "DNS", "SMTP", "UNKNOWN"}):
        raise ValueError("Unsupported Alert protocol/application_protocol")
    if type(alert.timestamp) not in (int, float):
        raise ValueError("Alert timestamp must be finite non-negative epoch seconds")
    try:
        timestamp = float(alert.timestamp)
    except OverflowError as exc:
        raise ValueError("Alert timestamp exceeds the supported numeric range") from exc
    if not math.isfinite(timestamp) or timestamp < 0:
        raise ValueError("Alert timestamp must be finite non-negative epoch seconds")
    return timestamp


def compute_statistics(
    alerts: Iterable[Alert], config: ReportConfig | None = None,
) -> ReportStatistics:
    """Accumulate each supplied repository row once, without mutating input.

    The generator supplies the unique-ID rows returned by Repository.query().
    No further deduplication, filtering or aggregation is performed here.
    Counter sums use Python integers, avoiding SQLite SUM integer overflow.
    """
    config = config if config is not None else ReportConfig()
    if not isinstance(config, ReportConfig):
        raise TypeError("Expected ReportConfig")
    tables: dict[str, _Table] = {field: {} for field in _FIELDS}
    buckets: dict[int, tuple[int, int]] = {}
    seconds = 3600 if config.time_bucket == "hour" else 60
    total_alerts = total_count = 0
    for alert in alerts:
        timestamp = _timestamp(alert)
        total_alerts += 1
        total_count += alert.count
        for field, table in tables.items():
            value = getattr(alert, field)
            groups, count = table.get(value, (0, 0))
            table[value] = groups + 1, count + alert.count
        # Integer arithmetic avoids datetime year limits and floating-point
        # division rounding at bucket boundaries. Timestamps are non-negative.
        start = (int(timestamp) // seconds) * seconds
        groups, count = buckets.get(start, (0, 0))
        buckets[start] = groups + 1, count + alert.count
    return ReportStatistics(
        total_alerts=total_alerts,
        total_count=total_count,
        severity_distribution=_rows(tables["severity"], _SEVERITIES),
        sid_statistics=_rows(tables["sid"]),
        classtype_statistics=_rows(tables["classtype"]),
        top_sids=_top(tables["sid"], config.top_n),
        top_src_ips=_top(tables["src_ip"], config.top_n),
        top_dst_ips=_top(tables["dst_ip"], config.top_n),
        transport_protocol_distribution=_rows(tables["protocol"]),
        application_protocol_distribution=_rows(tables["application_protocol"]),
        time_series=tuple(TimeBucketStatistics(start, start + seconds, *buckets[start]) for start in sorted(buckets)),
    )
