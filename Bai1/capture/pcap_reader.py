import json

from scapy.utils import PcapReader

from output.jsonl_writer import JSONLWriter
from parsers.packet_parser import process_packet


def read_pcap(
    file_path: str,
    output_path: str,
) -> None:
    """
    Read packets from a PCAP file.

    Every packet is sent through the common parsing pipeline
    and written to a JSON Lines output file.
    """

    print(
        f"[PCAP MODE] Reading packets from: "
        f"{file_path}"
    )

    packet_count = 0

    try:
        with JSONLWriter(output_path) as writer:

            with PcapReader(file_path) as pcap_reader:

                for packet_id, packet in enumerate(
                    pcap_reader,
                    start=1,
                ):
                    event = process_packet(
                        packet,
                        packet_id,
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

                    packet_count += 1

    except FileNotFoundError:
        print(
            f"[ERROR] PCAP file not found: "
            f"{file_path}"
        )

        return

    except PermissionError:
        print(
            f"[ERROR] Permission denied: "
            f"{file_path}"
        )

        return

    except Exception as exc:
        print(
            "[ERROR] Failed to process PCAP file: "
            f"{type(exc).__name__}: {exc}"
        )

        return

    print(
        f"[PCAP MODE] Processed "
        f"{packet_count} packets."
    )

    print(
        f"[OUTPUT] JSONL file: "
        f"{output_path}"
    )