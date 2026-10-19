"""Define normalized event and flow context types."""

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
    # Missing payload_hex means unavailable bytes, not an empty payload.
    payload_hex: str


class ApplicationFields(TypedDict, total=False):
    """Describe common application fields."""

    protocol: str
    decode_status: str
    decode_reason: str | None


class Endpoint(TypedDict):
    ip: str
    port: int


class FlowContext(TypedDict, total=False):
    """
    Describe flow metadata without assuming client/server direction.
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
    # Optional enrichment; absent means UNKNOWN, regardless of forward/backward.
    client_server_direction: ClientServerDirection


class _EventFields(TypedDict):
    timestamp: float | None
    network: NetworkFields
    transport: TransportFields
    application: ApplicationFields


class NormalizedEvent(_EventFields, total=False):
    """
    Describe normalized events from the existing pipeline.
    """

    packet_id: int
    preprocess_status: Literal["valid", "partial", "invalid"]
    processing_action: Literal["continue", "skip"]
    flow: FlowContext
