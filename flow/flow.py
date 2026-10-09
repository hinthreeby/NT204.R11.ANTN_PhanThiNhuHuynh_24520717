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
    Store identity, endpoints, and TCP state
    for one bidirectional flow.
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

    # TCP connection tracking
    tcp_state: str | None = None

    syn_seen: bool = False
    syn_ack_seen: bool = False
    syn_origin_direction: str | None = None

    fin_forward_seen: bool = False
    fin_backward_seen: bool = False

    def __post_init__(
        self,
    ) -> None:
        """
        Initialize protocol-specific state.
        """

        if self.protocol == "TCP":
            self.tcp_state = "NEW"

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

    def update_tcp_state(
        self,
        flags,
        direction: str,
    ) -> None:
        """
        Update the logical TCP connection state.

        Supported transitions:
        NEW -> HANDSHAKE -> ESTABLISHED
        ESTABLISHED -> CLOSING -> CLOSED
        Any active state -> RESET on RST
        """

        if self.protocol != "TCP":
            return

        if isinstance(
            flags,
            str,
        ):
            flag_set = {
                flags.upper()
            }

        elif isinstance(
            flags,
            (list, tuple, set),
        ):
            flag_set = {
                str(flag).upper()
                for flag in flags
            }

        else:
            flag_set = set()

        # RST has highest priority
        if "RST" in flag_set:
            self.tcp_state = "RESET"
            return

        # Terminal states stay terminal.
        if self.tcp_state in {
            "CLOSED",
            "RESET",
        }:
            return

        # Connection closing
        if "FIN" in flag_set:
            if direction == "forward":
                self.fin_forward_seen = True

            elif direction == "backward":
                self.fin_backward_seen = True

            if (
                self.fin_forward_seen
                and self.fin_backward_seen
            ):
                self.tcp_state = "CLOSED"

            else:
                self.tcp_state = "CLOSING"

            return

        # NEW
        if self.tcp_state == "NEW":
            # Normal first handshake packet: SYN
            if (
                "SYN" in flag_set
                and "ACK" not in flag_set
            ):
                self.syn_seen = True

                self.syn_origin_direction = (
                    direction
                )

                self.tcp_state = (
                    "HANDSHAKE"
                )

                return

            # Capture may begin from SYN/ACK.
            if (
                "SYN" in flag_set
                and "ACK" in flag_set
            ):
                self.syn_ack_seen = True

                self.tcp_state = (
                    "HANDSHAKE"
                )

                return

        # HANDSHAKE
        if (
            self.tcp_state
            == "HANDSHAKE"
        ):
            # SYN/ACK should normally travel
            # opposite to the initial SYN.
            if (
                "SYN" in flag_set
                and "ACK" in flag_set
            ):
                if (
                    self.syn_origin_direction
                    is None
                    or direction
                    != self.syn_origin_direction
                ):
                    self.syn_ack_seen = True

                return

            # Final ACK completes the three-way handshake.
            if (
                "ACK" in flag_set
                and "SYN" not in flag_set
                and self.syn_seen
                and self.syn_ack_seen
            ):
                if (
                    self.syn_origin_direction
                    is None
                    or direction
                    == self.syn_origin_direction
                ):
                    self.tcp_state = (
                        "ESTABLISHED"
                    )

                return

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
            "state": (
                self.tcp_state
                if self.protocol == "TCP"
                else None
            ),
        }