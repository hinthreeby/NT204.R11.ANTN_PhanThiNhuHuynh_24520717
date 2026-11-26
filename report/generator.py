"""Read repository snapshots for a time range and return structured statistics."""

from dataclasses import dataclass
import math
from typing import Literal, Protocol

from alert.models import Alert
from .statistics import ReportConfig, ReportStatistics, compute_statistics


class AlertReader(Protocol):
    """Minimum read-only API; AlertRepository supplies this query interface."""

    def query(
        self, *, from_time: float | int | None = None, to_time: float | int | None = None,
    ) -> list[Alert]:
        ...


@dataclass(frozen=True, slots=True)
class Report:
    """Structured report with explicit time and ranking policy; not a formatter.

    total_count includes the full count of each selected group. Each group's
    weight belongs to its opening timestamp/bucket, not individual member times.
    """

    from_time: float | None
    to_time: float | None
    config: ReportConfig
    statistics: ReportStatistics
    timezone: Literal["UTC"] = "UTC"
    time_field: Literal["timestamp"] = "timestamp"
    range_policy: Literal["[from_time, to_time)"] = "[from_time, to_time)"
    ranking_basis: Literal["total_count"] = "total_count"


def _bound(value: float | int | None, name: str) -> float | None:
    if value is None:
        return None
    if type(value) not in (int, float):
        raise ValueError(f"{name} must be finite non-negative epoch seconds or None")
    try:
        number = float(value)
    except OverflowError as exc:
        raise ValueError(f"{name} exceeds the supported numeric range") from exc
    if not math.isfinite(number) or number < 0:
        raise ValueError(f"{name} must be finite non-negative epoch seconds")
    return number


class ReportGenerator:
    """Read through query() only; never open, write, close or reset a repository.

    Time bounds follow Repository.query(): optional UTC epoch seconds, inclusive
    from_time and exclusive to_time. Equal bounds give an empty report. Storage
    errors propagate instead of being disguised as an empty report.
    """

    def __init__(self, repository: AlertReader, config: ReportConfig | None = None) -> None:
        if not callable(getattr(repository, "query", None)):
            raise TypeError("Expected a repository with query()")
        config = config if config is not None else ReportConfig()
        if not isinstance(config, ReportConfig):
            raise TypeError("Expected ReportConfig")
        self._repository = repository
        self._config = config

    @property
    def config(self) -> ReportConfig:
        return self._config

    def generate(
        self, *, from_time: float | int | None = None, to_time: float | int | None = None,
    ) -> Report:
        """Return a fresh report from exactly one repository query."""
        start, end = _bound(from_time, "from_time"), _bound(to_time, "to_time")
        if start is not None and end is not None and start > end:
            raise ValueError("from_time must be <= to_time")
        alerts = self._repository.query(from_time=start, to_time=end)
        return Report(start, end, self.config, compute_statistics(alerts, self.config))
