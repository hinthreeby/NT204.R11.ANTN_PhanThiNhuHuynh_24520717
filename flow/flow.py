from dataclasses import dataclass
from hashlib import sha256


Endpoint = tuple[str, int]
FlowKey = tuple[str, int, str, int, str]


def build_flow_key(
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str,
) -> FlowKey:
    """
    Build a canonical bidirectional flow key.

    Reversing source and destination produces the same key.
    """

    source: Endpoint = (
        src_ip,
        src_port,
    )

    destination: Endpoint = (
        dst_ip,
        dst_port,
    )

    first, second = sorted(
        (source, destination)
    )

    return (
        first[0],
        first[1],
        second[0],
        second[1],
        protocol.upper(),
    )


def create_flow_id(
    flow_key: FlowKey,
    start_time: float,
) -> str:
    """
    Create a stable identifier for one active flow instance.
    """

    material = "|".join(
        str(value)
        for value in (
            *flow_key,
            start_time,
        )
    )

    digest = sha256(
        material.encode("utf-8")
    ).hexdigest()[:16]

    return f"flow-{digest}"


@dataclass
class Flow:
    """
    Store the identity and endpoints of one bidirectional flow.
    """

    flow_id: str
    key: FlowKey
    protocol: str

    endpoint_a_ip: str
    endpoint_a_port: int

    endpoint_b_ip: str
    endpoint_b_port: int

    application_protocol: str

    start_time: float
    last_seen: float

    def get_direction(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> str:
        """
        Return packet direction relative to the first packet.
        """

        if (
            src_ip == self.endpoint_a_ip
            and src_port == self.endpoint_a_port
            and dst_ip == self.endpoint_b_ip
            and dst_port == self.endpoint_b_port
        ):
            return "forward"

        if (
            src_ip == self.endpoint_b_ip
            and src_port == self.endpoint_b_port
            and dst_ip == self.endpoint_a_ip
            and dst_port == self.endpoint_a_port
        ):
            return "backward"

        return "unknown"

    def update_application_protocol(
        self,
        application_protocol: str,
    ) -> None:
        """
        Keep the first useful application protocol observed.
        """

        if (
            self.application_protocol == "UNKNOWN"
            and application_protocol != "UNKNOWN"
        ):
            self.application_protocol = (
                application_protocol
            )

    def to_event_metadata(
        self,
        direction: str,
    ) -> dict:
        """
        Build JSON-compatible flow metadata for an event.
        """

        return {
            "tracked": True,
            "flow_id": self.flow_id,
            "direction": direction,
            "protocol": self.protocol,
            "application_protocol": (
                self.application_protocol
            ),
            "endpoint_a": {
                "ip": self.endpoint_a_ip,
                "port": self.endpoint_a_port,
            },
            "endpoint_b": {
                "ip": self.endpoint_b_ip,
                "port": self.endpoint_b_port,
            },
            "start_time": self.start_time,
            "last_seen": self.last_seen,
        }