from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from .models import Severity


SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})


@dataclass(frozen=True, slots=True)
class SeverityConfig:
    """Configure project severity policy independently of Snort matching."""

    priority_mapping: Mapping[int, Severity] = field(default_factory=lambda: {
        1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW",
    })
    missing_severity: Severity = "MEDIUM"
    unmapped_severity: Severity = "LOW"

    def __post_init__(self) -> None:
        if not isinstance(self.priority_mapping, Mapping):
            raise ValueError("priority_mapping must be a mapping")
        mapping = dict(self.priority_mapping)
        for priority, severity in mapping.items():
            if type(priority) is not int or priority < 1:
                raise ValueError("Priority mapping keys must be positive integers")
            if not isinstance(severity, str) or severity not in SEVERITIES:
                raise ValueError("Invalid mapped severity")
        for severity in (self.missing_severity, self.unmapped_severity):
            if not isinstance(severity, str) or severity not in SEVERITIES:
                raise ValueError("Invalid fallback severity")
        object.__setattr__(self, "priority_mapping", MappingProxyType(mapping))

    def severity_for(self, priority: int | None) -> Severity:
        """Resolve a validated priority without treating invalid data as missing."""

        if priority is None:
            return self.missing_severity
        if type(priority) is not int or priority < 1:
            raise ValueError("priority must be a positive integer or None")
        return self.priority_mapping.get(priority, self.unmapped_severity)
