import json
import logging

from scapy.layers.inet import IP
from scapy.sendrecv import sniff

from output.jsonl_writer import JSONLWriter


logger = logging.getLogger(__name__)


def capture_live(
    interface: str,
    output_path: str,
    packet_processor,
) -> None:
    """
    Capture IPv4 packets from a network interface.
    """

    print(
        f"[LIVE MODE] Capturing packets from interface: "
        f"{interface}"
    )

    print(
        "[LIVE MODE] Ctrl+C to stop capturing."
    )

    packet_count = 0
    processing_error = None

    with JSONLWriter(output_path) as writer:

        def handle_packet(packet) -> None:
            """Process a packet and retain failures for the caller."""

            nonlocal packet_count, processing_error

            if processing_error is not None:
                return
            try:
                packet_count += 1

                event = packet_processor(
                    packet,
                    packet_count,
                )

                writer.write_event(
                    event
                )

                print(
                    json.dumps(
                        event,
                        indent=2,
                        ensure_ascii=False,
                    )
                )
            except Exception as exc:
                # Scapy can swallow callback exceptions as socket errors.
                processing_error = exc

        try:
            sniff(
                iface=interface,
                prn=handle_packet,
                store=False,
                lfilter=lambda packet: IP in packet,
                stop_filter=lambda packet: processing_error is not None,
            )
        except KeyboardInterrupt:
            pass
        except Exception as exc:
            if processing_error is None:
                if isinstance(exc, PermissionError):
                    print(
                        "[ERROR] Permission denied while capturing "
                        f"from interface: {interface}"
                    )
                elif isinstance(exc, OSError):
                    print(
                        "[ERROR] Failed to access network interface: "
                        f"{type(exc).__name__}: {exc}"
                    )
                else:
                    print(f"[ERROR] Live capture failed: {type(exc).__name__}: {exc}")
                return
            logger.exception("Live capture cleanup failed; preserving the original processing exception")

        if processing_error is not None:
            raise processing_error.with_traceback(processing_error.__traceback__)

    print(
        f"[LIVE MODE] Captured "
        f"{packet_count} IPv4 packets."
    )

    print(
        f"[OUTPUT] JSONL file: "
        f"{output_path}"
    )