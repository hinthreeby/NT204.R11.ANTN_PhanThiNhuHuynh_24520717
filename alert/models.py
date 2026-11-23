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
class AlertResult:
    """Describe alert creation or a rejected Detection Event."""

    status: Literal["created", "rejected"]
    alert: Alert | None
    reason: str | None
