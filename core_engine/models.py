"""Internal rule and result shapes, with no parsing, validation or matching.

Dataclasses provide structure only, not runtime validity checks. The future
validator owns syntax and supported-keyword checks. JSON output can use
dataclasses.asdict(); byte evidence is represented as hex strings.
"""

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
    """Selectors retain any/IP/CIDR and any/single/range port expressions.

    The parser will validate these strings; this model does not interpret them.
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
    """Ordered options preserve repeated content and their modifier positions.

    Values are textual at this stage; a later parser defines their semantics.
    None represents a valueless option, not a missing required value.
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
    """Identify the matched buffer/field explicitly.

    Optional start/end are zero-based byte offsets, end exclusive, in that
    buffer. transport.payload_hex denotes its decoded bytes, not hex characters.
    Application buffers must declare their byte representation before matching.
    """

    field: str
    start: int | None = None
    end: int | None = None
    matched_hex: str | None = None


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
