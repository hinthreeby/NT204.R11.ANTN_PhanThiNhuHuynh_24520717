import json

from scapy.layers.inet import IP
from scapy.sendrecv import sniff

from output.jsonl_writer import JSONLWriter
from parsers.packet_parser import process_packet


def capture_live(
    interface: str,
    output_path: str,
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

    try:
        with JSONLWriter(output_path) as writer:

            def handle_packet(packet) -> None:
                """
                Process one captured packet immediately.
                """

                nonlocal packet_count

                packet_count += 1

                event = process_packet(
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

            try:
                sniff(
                    iface=interface,
                    prn=handle_packet,
                    store=False,
                    lfilter=lambda packet: IP in packet,
                )

            except KeyboardInterrupt:
                pass

    except PermissionError:
        print(
            "[ERROR] Permission denied while capturing "
            f"from interface: {interface}"
        )

        return

    except OSError as exc:
        print(
            "[ERROR] Failed to access network interface: "
            f"{type(exc).__name__}: {exc}"
        )

        return

    except Exception as exc:
        print(
            "[ERROR] Live capture failed: "
            f"{type(exc).__name__}: {exc}"
        )

        return

    print(
        f"[LIVE MODE] Captured "
        f"{packet_count} IPv4 packets."
    )

    print(
        f"[OUTPUT] JSONL file: "
        f"{output_path}"
    )