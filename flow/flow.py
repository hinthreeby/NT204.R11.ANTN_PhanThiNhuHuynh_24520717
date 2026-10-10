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

    # Flow statistics
    packet_count: int = 0
    byte_count: int = 0

    forward_packet_count: int = 0
    forward_byte_count: int = 0

    backward_packet_count: int = 0
    backward_byte_count: int = 0

    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0

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
        direction: str | None,
    ) -> dict:
        """
        Build JSON-compatible flow metadata.
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
            "duration": self.get_duration(),

            "packet_count": (
                self.packet_count
            ),

            "byte_count": (
                self.byte_count
            ),

            "forward_packet_count": (
                self.forward_packet_count
            ),

            "forward_byte_count": (
                self.forward_byte_count
            ),

            "backward_packet_count": (
                self.backward_packet_count
            ),

            "backward_byte_count": (
                self.backward_byte_count
            ),

            "SYN_count": (
                self.syn_count
            ),

            "ACK_count": (
                self.ack_count
            ),

            "FIN_count": (
                self.fin_count
            ),

            "RST_count": (
                self.rst_count
            ),

            "state": (
                self.tcp_state
                if self.protocol == "TCP"
                else None
            ),
        }

    def update_statistics(
        self,
        packet_size: int,
        flags,
        direction: str,
        timestamp: float,
    ) -> None:
        """
        Update packet, byte, direction, TCP flag,
        and timing statistics for this flow.
        """

        packet_size = max(
            int(packet_size),
            0,
        )

        # Overall counters
        self.packet_count += 1
        self.byte_count += packet_size

        # Direction counters
        if direction == "forward":
            self.forward_packet_count += 1
            self.forward_byte_count += (
                packet_size
            )

        elif direction == "backward":
            self.backward_packet_count += 1
            self.backward_byte_count += (
                packet_size
            )

        # TCP flag counters
        if self.protocol == "TCP":
            if isinstance(flags, str):
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

            if "SYN" in flag_set:
                self.syn_count += 1

            if "ACK" in flag_set:
                self.ack_count += 1

            if "FIN" in flag_set:
                self.fin_count += 1

            if "RST" in flag_set:
                self.rst_count += 1

        # Timing
        self.last_seen = max(
            self.last_seen,
            timestamp,
        )

    def get_duration(
        self,
    ) -> float:
        """
        Return flow duration in seconds.
        """

        return max(
            0.0,
            self.last_seen
            - self.start_time,
        )

    def to_expired_summary(
        self,
        close_reason: str,
    ) -> dict:
        """
        Build a summary for an expired flow.
        """

        summary = self.to_event_metadata(
            direction=None
        )

        summary.pop(
            "direction",
            None,
        )

        summary["expired"] = True

        summary["close_reason"] = (
            close_reason
        )

        return summary