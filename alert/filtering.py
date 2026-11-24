from dataclasses import dataclass, field
from ipaddress import IPv4Address
from types import MappingProxyType

from .models import AlertResult, Severity


SEVERITY_RANK = MappingProxyType({"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3})


def _collection(value, name: str) -> tuple:
    if not isinstance(value, (set, frozenset, list, tuple)):
        raise ValueError(f"{name} must be a set, frozenset, list or tuple")
    return tuple(value)


def _ip_allowlist(value, name: str) -> frozenset[str] | None:
    if value is None:
        return None
    normalized = []
    for address in _collection(value, name):
        if not isinstance(address, str):
            raise ValueError(f"{name} requires IPv4 strings")
        try:
            normalized.append(str(IPv4Address(address.strip())))
        except ValueError as exc:
            raise ValueError(f"Invalid IPv4 in {name}") from exc
    return frozenset(normalized)


@dataclass(frozen=True, slots=True)
class AlertFilterConfig:
    """Snapshot filter policy; None disables a threshold or allowlist."""

    minimum_severity: Severity | None = None
    suppressed_sids: frozenset[int] = field(default_factory=frozenset)
    allowed_src_ips: frozenset[str] | None = None
    allowed_dst_ips: frozenset[str] | None = None
    allowed_protocols: frozenset[str] | None = None

    def __post_init__(self) -> None:
        minimum = self.minimum_severity
        if minimum is not None:
            if not isinstance(minimum, str) or minimum.strip().upper() not in SEVERITY_RANK:
                raise ValueError("minimum_severity must be CRITICAL, HIGH, MEDIUM, LOW or None")
            object.__setattr__(self, "minimum_severity", minimum.strip().upper())
        sids = _collection(self.suppressed_sids, "suppressed_sids")
        if any(type(sid) is not int or sid < 1 for sid in sids):
            raise ValueError("suppressed_sids requires positive integer SIDs")
        object.__setattr__(self, "suppressed_sids", frozenset(sids))
        for name in ("allowed_src_ips", "allowed_dst_ips"):
            object.__setattr__(self, name, _ip_allowlist(getattr(self, name), name))
        if self.allowed_protocols is not None:
            protocols = _collection(self.allowed_protocols, "allowed_protocols")
            if any(not isinstance(protocol, str) or protocol.strip().upper() not in {"TCP", "UDP"}
                   for protocol in protocols):
                raise ValueError("allowed_protocols requires TCP or UDP strings")
            object.__setattr__(self, "allowed_protocols", frozenset(p.strip().upper() for p in protocols))


def filter_detection(fields: dict, severity: Severity, config: AlertFilterConfig) -> AlertResult | None:
    """Return a policy rejection for validated fields, or None to allow creation."""

    sid = fields["sid"]
    if sid in config.suppressed_sids:
        return AlertResult("suppressed", None, f"SID {sid} is suppressed")
    minimum = config.minimum_severity
    if minimum is not None and SEVERITY_RANK[severity] < SEVERITY_RANK[minimum]:
        return AlertResult("filtered", None, f"Severity {severity} is below minimum {minimum}")
    for field_name, allowed in (
        ("src_ip", config.allowed_src_ips), ("dst_ip", config.allowed_dst_ips),
        ("protocol", config.allowed_protocols),
    ):
        if allowed is not None and fields[field_name] not in allowed:
            return AlertResult("filtered", None, f"{field_name} is not allowed by filter policy")
    return None
