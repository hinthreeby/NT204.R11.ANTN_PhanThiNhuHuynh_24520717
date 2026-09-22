import argparse

from capture.live_capture import capture_live
from capture.pcap_reader import read_pcap


def build_argument_parser() -> argparse.ArgumentParser:
    """
    Build the command-line interface for the packet capture/parser.
    """

    parser = argparse.ArgumentParser(
        description="Packet Capture & Parser for IDS"
    )

    input_group = parser.add_mutually_exclusive_group(required=True)

    input_group.add_argument(
        "--interface",
        type=str,
        help="Network interface used for live packet capture, e.g. eth0",
    )

    input_group.add_argument(
        "--pcap",
        type=str,
        help="Path to a PCAP file to process",
    )

    parser.add_argument(
        "--output",
        type=str,
        default="output/events.jsonl",
        help=(
            "Path to the JSON Lines output file "
            "(default: output/events.jsonl)"
        ),
    )

    return parser


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()

    if args.interface:
        capture_live(
            args.interface,
            args.output,
        )

    elif args.pcap:
        read_pcap(
            args.pcap,
            args.output,
        )


if __name__ == "__main__":
    main()