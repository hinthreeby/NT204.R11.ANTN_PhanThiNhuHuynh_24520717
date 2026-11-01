import json
from contextlib import closing
import logging
import sys

from scapy.utils import PcapReader

from output.jsonl_writer import JSONLWriter


logger = logging.getLogger(__name__)


class _PcapInputError(Exception):
    """Identify failures originating from the PCAP input."""


def _read_packets(file_path: str):
    """Yield packets while keeping input failures separate from consumers."""

    try:
        reader = PcapReader(file_path)
    except Exception as exc:
        raise _PcapInputError from exc
    try:
        while True:
            try:
                packet = next(reader)
            except StopIteration:
                break
            except Exception as exc:
                raise _PcapInputError from exc
            yield packet
    finally:
        active_error = sys.exc_info()[1]
        try:
            reader.close()
        except Exception as exc:
            if active_error is None:
                raise _PcapInputError from exc
            logger.exception("PCAP input cleanup failed; preserving the original exception")


def read_pcap(
    file_path: str,
    output_path: str,
    packet_processor,
) -> None:
    """
    Read packets from a PCAP file.
    """
    print(
        f"[PCAP MODE] Reading packets from: "
        f"{file_path}"
    )

    packet_count = 0

    with JSONLWriter(output_path) as writer:
        try:
            with closing(_read_packets(file_path)) as packets:

                for packet_id, packet in enumerate(
                    packets,
                    start=1,
                ):
                    event = packet_processor(
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

        except _PcapInputError as failure:
            exc = failure.__cause__
            if isinstance(exc, FileNotFoundError):
                print(f"[ERROR] PCAP file not found: {file_path}")
            elif isinstance(exc, PermissionError):
                print(f"[ERROR] Permission denied: {file_path}")
            else:
                print(f"[ERROR] Failed to process PCAP file: {type(exc).__name__}: {exc}")
            return

    print(
        f"[PCAP MODE] Processed "
        f"{packet_count} packets."
    )

    print(
        f"[OUTPUT] JSONL file: "
        f"{output_path}"
    )
