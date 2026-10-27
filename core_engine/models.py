"""Define internal rule and detection result models."""

from dataclasses import dataclass
from typing import Literal

from .contracts import TransportProtocol


@dataclass(frozen=True, slots=True)
class RuleText:
    text: str
    source: str
    line_number: int


@dataclass(frozen=True, slots=True)
class RuleHeader:
    """
    Store rule header fields.
    """

    action: Literal["alert"]
    protocol: Literal["tcp", "udp"]
    src_ip: str
    src_port: str
    direction: Literal["->", "<>"]
    dst_ip: str
    dst_port: str


@dataclass(frozen=True, slots=True)
class RuleOption:
    """
    Store a rule option without changing its value.
    """

    name: str
    value: str | None


@dataclass(frozen=True, slots=True)
class InternalRule:
    header: RuleHeader
    sid: int
    rev: int
    msg: str
    options: tuple[RuleOption, ...]
    priority: int | None = None
    classtype: str | None = None


@dataclass(frozen=True, slots=True)
class RuleValidationResult:
    source: RuleText
    status: Literal["valid", "invalid", "unsupported"]
    rule: InternalRule | None
    reason: str | None


@dataclass(frozen=True, slots=True)
class MatchInformation:
    """
    Store matched bytes and their location in a buffer.
    """

    field: str
    # Offsets count bytes, not hex characters; end is exclusive.
    start: int | None = None
    end: int | None = None
    matched_hex: str | None = None
    # Zero-based index in InternalRule.options, when tied to one content.
    option_index: int | None = None


@dataclass(frozen=True, slots=True)
class MatchResult:
    rule: InternalRule
    status: Literal["MATCH", "NO_MATCH"]
    information: tuple[MatchInformation, ...]
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class DetectionEvent:
    timestamp: float
    sid: int
    rev: int
    msg: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: TransportProtocol
    application_protocol: str
    flow_id: str | None
    match_information: tuple[MatchInformation, ...]
    priority: int | None = None
    classtype: str | None = None


@dataclass(frozen=True, slots=True)
class CoreEngineResult:
    matches: tuple[MatchResult, ...]
    detection_events: tuple[DetectionEvent, ...]
