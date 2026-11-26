"""Read-only report statistics and explicit text/JSON presentation."""

from .generator import AlertReader, Report, ReportGenerator
from .formatter import ReportFormatter
from .statistics import (
    CategoryStatistics, ReportConfig, ReportStatistics, TimeBucketStatistics, compute_statistics,
)


__all__ = [
    "AlertReader", "CategoryStatistics", "Report", "ReportConfig", "ReportGenerator",
    "ReportFormatter", "ReportStatistics", "TimeBucketStatistics", "compute_statistics",
]
