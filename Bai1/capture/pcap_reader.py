import json

from scapy.utils import PcapReader

from parsers.packet_parser import process_packet


def read_pcap(file_path: str) -> None:
    """
    Read packets from a PCAP file and send every packet
    through the common parsing pipeline.
    """

    print(f"[PCAP MODE] Reading packets from: {file_path}")

    packet_count = 0

    try:
        with PcapReader(file_path) as pcap_reader:
            for packet_id, packet in enumerate(pcap_reader, start=1):
                event = process_packet(packet, packet_id)

                print(
                    json.dumps(
                        event,
                        indent=2,
                        ensure_ascii=False
                    )
                )

                packet_count += 1

    except FileNotFoundError:
        print(f"[ERROR] PCAP file not found: {file_path}")
        return

    print(f"[PCAP MODE] Processed {packet_count} packets.")