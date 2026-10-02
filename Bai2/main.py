import argparse
import json
from pathlib import Path

from pipeline import Bai2Pipeline


def build_argument_parser() -> argparse.ArgumentParser:
    """
    Build the command-line interface for Bai2.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Decoder, Preprocessor, "
            "and Flow/Connection Tracker"
        )
    )

    parser.add_argument(
        "--input",
        required=True,
        help=(
            "Path to a JSONL file containing "
            "normalized events from Bai1"
        ),
    )

    parser.add_argument(
        "--output",
        default="output/events.jsonl",
        help=(
            "Path to the processed JSONL output "
            "(default: output/events.jsonl)"
        ),
    )

    return parser


def process_jsonl(
    input_path: str,
    output_path: str,
) -> None:
    """
    Read normalized Bai1 events from JSONL and process
    them through the Bai2 pipeline.
    """

    pipeline = Bai2Pipeline()

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
            mode="r",
            encoding="utf-8",
        ) as source:

            with output_file.open(
                mode="w",
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
        f"[Bai2] Processed events: "
        f"{processed_count}"
    )

    print(
        f"[Bai2] Skipped events: "
        f"{skipped_count}"
    )

    print(
        f"[OUTPUT] JSONL file: "
        f"{output_path}"
    )


def main() -> None:
    parser = build_argument_parser()

    args = parser.parse_args()

    process_jsonl(
        input_path=args.input,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()