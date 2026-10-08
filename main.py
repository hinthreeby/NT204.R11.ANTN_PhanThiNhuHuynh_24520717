import argparse
import json
from pathlib import Path

from capture.live_capture import capture_live
from capture.pcap_reader import read_pcap
from pipeline import IDSPipeline


def build_argument_parser() -> argparse.ArgumentParser:
    """
    Build the command-line interface for the IDS pipeline.
    """

    parser = argparse.ArgumentParser(
        description="IDS processing pipeline"
    )

    input_group = parser.add_mutually_exclusive_group(
        required=True
    )

    input_group.add_argument(
        "--pcap",
        help="Path to a PCAP file",
    )

    input_group.add_argument(
        "--interface",
        help="Network interface for live capture",
    )

    input_group.add_argument(
        "--events",
        "--input",
        dest="events",
        help=(
            "Path to normalized JSONL events "
            "for direct module testing"
        ),
    )

    parser.add_argument(
        "--output",
        default="output/events.jsonl",
        help="Path to JSONL output file",
    )

    return parser


def process_event_file(
    input_path: str,
    output_path: str,
    pipeline: IDSPipeline,
) -> None:
    """
    Process normalized JSONL events through Decoder,
    Preprocessor, and Flow Tracker.
    """

    input_file = Path(input_path)
    output_file = Path(output_path)

    output_file.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    processed_count = 0
    skipped_count = 0

    try:
        with input_file.open(
            "r",
            encoding="utf-8",
        ) as source:

            with output_file.open(
                "w",
                encoding="utf-8",
            ) as destination:

                for line_number, line in enumerate(
                    source,
                    start=1,
                ):
                    line = line.strip()

                    if not line:
                        continue

                    try:
                        event = json.loads(
                            line
                        )

                    except json.JSONDecodeError as exc:
                        print(
                            f"[ERROR] Invalid JSON at "
                            f"line {line_number}: {exc}"
                        )

                        skipped_count += 1
                        continue

                    result = pipeline.process_event(
                        event
                    )

                    if result is None:
                        skipped_count += 1
                        continue

                    destination.write(
                        json.dumps(
                            result,
                            ensure_ascii=False,
                            separators=(",", ":"),
                        )
                        + "\n"
                    )

                    processed_count += 1

    except FileNotFoundError:
        print(
            f"[ERROR] Input file not found: "
            f"{input_path}"
        )

        return

    print(
        f"[IDS] Processed events: "
        f"{processed_count}"
    )

    print(
        f"[IDS] Skipped events: "
        f"{skipped_count}"
    )


def main() -> None:
    parser = build_argument_parser()

    args = parser.parse_args()

    pipeline = IDSPipeline()

    if args.pcap:
        read_pcap(
            args.pcap,
            args.output,
            pipeline.process_packet,
        )

    elif args.interface:
        capture_live(
            args.interface,
            args.output,
            pipeline.process_packet,
        )

    elif args.events:
        process_event_file(
            args.events,
            args.output,
            pipeline,
        )


if __name__ == "__main__":
    main()