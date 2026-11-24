from copy import deepcopy
from dataclasses import asdict, dataclass, field
from typing import Literal
from uuid import uuid4


Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@dataclass(frozen=True, slots=True, kw_only=True)
class Alert:
    """Store one normalized alert and its source match evidence."""

    alert_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: float
    sid: int
    rev: int
    message: str
    severity: Severity
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    application_protocol: str
    flow_id: str | None
    first_seen: float
    last_seen: float
    priority: int | None = None
    classtype: str | None = None
    count: int = 1
    match_information: tuple[dict, ...] = ()

    def to_dict(self) -> dict:
        """Return detached JSON-compatible alert fields."""

        record = asdict(self)
        record["match_information"] = deepcopy(list(self.match_information))
        return record


@dataclass(frozen=True, slots=True)
class AlertGroup:
    """Representative summary plus lossless source metadata in arrival order.

    summary keeps the opening event's metadata, timestamp and group ID; only
    count and last_seen change. members retain every original Alert, including
    its own ID, flow, ports, severity, revision and match evidence.
    """

    summary: Alert
    members: tuple[Alert, ...]


@dataclass(frozen=True, slots=True)
class AlertResult:
    """Describe policy decisions and the current/finalized aggregation views.

    With aggregation enabled, created opens a group; aggregated updates it.
    finalized identifies a late singleton already included in finalized, which
    must be consumed only once. When group is present, alert is its summary.
    group and finalized are absent/empty when disabled or input is blocked.

    A future repository can insert created groups, update aggregated groups by
    alert_id, and upsert/close finalized groups (also returned by manager.flush).
    Disabled created alerts are independent records ready for insertion.
    No repository writes occur here. Existing three-argument calls remain valid.
    """

    status: Literal["created", "aggregated", "finalized", "rejected", "filtered", "suppressed"]
    alert: Alert | None
    reason: str | None
    group: AlertGroup | None = field(default=None, kw_only=True)
    finalized: tuple[AlertGroup, ...] = field(default=(), kw_only=True)
