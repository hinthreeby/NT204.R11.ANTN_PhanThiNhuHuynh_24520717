"""Dictionary contracts for existing pipeline data, without packet-library types.

These annotations do not validate events at runtime or change the pipeline schema.
Missing legacy payload_hex means unavailable bytes, not an empty payload. Future
consumers must validate hex before bytes.fromhex(); payload_length is transport
data size, while network.total_length includes IPv4 and transport headers.
Skip/invalid events must be filtered before evaluation; partial events can only
be evaluated using fields known to be valid. No decoded text replaces raw bytes.
"""

from typing import Literal, TypedDict


TransportProtocol = Literal["TCP", "UDP"]
FlowDirection = Literal["forward", "backward", "unknown"]
ClientServerDirection = Literal["to_server", "to_client", "UNKNOWN"]
TCPState = Literal["NEW", "HANDSHAKE", "ESTABLISHED", "CLOSING", "CLOSED", "RESET"]


class NetworkFields(TypedDict, total=False):
    protocol: str
    src_ip: str
    dst_ip: str
    total_length: int | None


class TransportFields(TypedDict, total=False):
    protocol: str
    src_port: int | None
    dst_port: int | None
    flags: list[str]
    payload_length: int
    payload_hex: str


class ApplicationFields(TypedDict, total=False):
    """Minimal view; existing HTTP/DNS/SMTP fields remain in the original dict."""

    protocol: str
    decode_status: str
    decode_reason: str | None


class Endpoint(TypedDict):
    ip: str
    port: int


class FlowContext(TypedDict, total=False):
    """View of event['flow']; unavailable metadata may be absent or None.

    A/B and forward/backward are relative to the first observed packet.
    client_server_direction is a proposed optional enrichment, NOT emitted by
    today's tracker. Absent means UNKNOWN; never infer it from direction alone.
    """

    tracked: bool
    flow_id: str | None
    direction: FlowDirection | None
    protocol: str
    application_protocol: str
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    state: TCPState | None
    start_time: float
    last_seen: float
    duration: float
    packet_count: int
    byte_count: int
    reason: str
    client_server_direction: ClientServerDirection


class _EventFields(TypedDict):
    timestamp: float | None
    network: NetworkFields
    transport: TransportFields
    application: ApplicationFields


class NormalizedEvent(_EventFields, total=False):
    """Read-only-by-convention view of the existing dict, not a replacement DTO.

    A future evaluation boundary must require valid timestamp, IPv4 addresses,
    TCP/UDP protocol and ports. Optional fields are capability-specific: missing
    flags, raw bytes or flow state must not become fabricated matching evidence.
    Extra existing parser/decoder/preprocessor/flow fields are preserved.
    """

    packet_id: int
    preprocess_status: Literal["valid", "partial", "invalid"]
    processing_action: Literal["continue", "skip"]
    flow: FlowContext
