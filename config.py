from dataclasses import dataclass


@dataclass
class IDSConfig:
    """
    Configuration values used by the IDS processing pipeline.
    """

    tcp_idle_timeout: float = 300.0
    udp_idle_timeout: float = 60.0

    max_decode_size: int = 65536

    skip_invalid_events: bool = False