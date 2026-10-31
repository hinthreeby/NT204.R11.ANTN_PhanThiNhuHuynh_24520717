import argparse
from contextlib import ExitStack
import json
from pathlib import Path

from capture.live_capture import capture_live
from capture.pcap_reader import read_pcap
from config import IDSConfig
from output.jsonl_writer import JSONLWriter
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

    parser.add_argument("--enable-core-engine", action="store_true", help="Enable rule evaluation and detection output")
    parser.add_argument("--rules", nargs="+", default=[], help="Rule files to load once at startup")
    parser.add_argument("--detection-output", help="Separate detection JSONL file (default: output/detections.jsonl)")
    parser.add_argument("--disable-rule", type=int, action="append", default=[], metavar="SID", help="Disable one SID; may be repeated")
    parser.add_argument("--disable-rule-file", action="append", default=[], metavar="PATH", help="Disable one rule file; may be repeated")

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


def run_pipeline(args: argparse.Namespace, pipeline: IDSPipeline) -> None:
    """Run the selected source through the shared IDS pipeline."""

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


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    if not args.enable_core_engine:
        if args.rules or args.detection_output or args.disable_rule or args.disable_rule_file:
            parser.error("Core Engine options require --enable-core-engine")
        run_pipeline(args, IDSPipeline())
        return
    if not args.rules:
        parser.error("--enable-core-engine requires --rules")
    if any(sid < 1 for sid in args.disable_rule):
        parser.error("--disable-rule requires a positive SID")
    config = IDSConfig(
        core_engine_enabled=True,
        rule_files=tuple(args.rules),
        disabled_rule_sids=tuple(args.disable_rule),
        disabled_rule_files=tuple(args.disable_rule_file),
    )
    if args.detection_output:
        config.detection_output = args.detection_output
    detection_path = Path(config.detection_output).resolve()
    protected = [args.output, *args.rules, *args.disable_rule_file]
    protected.extend(path for path in (args.pcap, args.events) if path)
    for path in protected:
        other = Path(path).resolve()
        if detection_path == other or (detection_path.exists() and other.exists() and detection_path.samefile(other)):
            parser.error("Detection output must differ from normalized output and input files")
    with ExitStack() as stack:
        writer = stack.enter_context(JSONLWriter(config.detection_output))
        pipeline = IDSPipeline(config, detection_sink=writer.write_event)
        run_pipeline(args, pipeline)


if __name__ == "__main__":
    main()
