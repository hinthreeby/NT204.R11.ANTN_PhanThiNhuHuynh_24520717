from config import IDSConfig
import logging
from pathlib import Path
from typing import Callable

from decoder.decoder import Decoder
from flow.flow_tracker import FlowTracker
from parsers.packet_parser import process_packet
from preprocessor.preprocessor import Preprocessor


logger = logging.getLogger(__name__)


class IDSPipeline:
    """
    Coordinate the complete IDS processing pipeline.

    Raw packet
        -> Packet Parser
        -> Decoder
        -> Preprocessor
        -> Flow Tracker
    """

    def __init__(
        self,
        config: IDSConfig | None = None,
        detection_sink: Callable[[dict], None] | None = None,
    ) -> None:
        if config is None:
            config = IDSConfig()

        self.config = config

        self.decoder = Decoder(
            config
        )

        self.preprocessor = Preprocessor(
            config
        )

        self.flow_tracker = FlowTracker(
            config
        )

        self.core_engine = None
        self.last_core_result = None
        self._detection_sink = detection_sink
        if config.core_engine_enabled:
            from core_engine.engine import CoreEngine
            from core_engine.rule_loader import RuleLoaderConfig

            if not config.rule_files:
                raise ValueError("Core Engine requires at least one rule file")
            self.core_engine = CoreEngine.from_rule_files(
                [Path(path) for path in config.rule_files],
                RuleLoaderConfig(
                    file_enabled={Path(path): False for path in config.disabled_rule_files},
                    rule_enabled={sid: False for sid in config.disabled_rule_sids},
                ),
            )

    def expire_idle_flows(self, current_time: float) -> list[dict]:
        """Return timeout summaries without requiring another packet.

        Use the same time domain as capture timestamps. This call neither
        flushes active flows at EOF nor adds time to packet durations.
        Skipped events do not implicitly consume summaries; callers can use
        this method to advance time explicitly and collect expired flows.
        """
        summaries = self.flow_tracker.expire_idle_flows(current_time)
        if self.core_engine is not None:
            for summary in summaries:
                self.core_engine.forget_flow(summary["flow_id"])
        return summaries

    def process_event(
        self,
        event: dict,
    ) -> dict | None:
        """
        Process one normalized IDS event.
        """

        self.last_core_result = None
        try:
            decoded_event = self.decoder.process(
                event
            )

            preprocessed_event = (
                self.preprocessor.process(
                    decoded_event
                )
            )

            if (
                preprocessed_event.get(
                    "processing_action"
                )
                == "skip"
            ):
                return None

            tracked_event = (
                self.flow_tracker.process(
                    preprocessed_event
                )
            )

        except Exception as exc:
            print(
                "[ERROR] IDS pipeline failed: "
                f"{type(exc).__name__}: {exc}"
            )

            return None

        if self.core_engine is not None:
            from core_engine.detection_event import DetectionEventDataError, DetectionEventGenerator

            try:
                result = self.core_engine.process(tracked_event, tracked_event.get("flow"))
            except DetectionEventDataError as exc:
                logger.error("Detection source data rejected: %s", exc)
            else:
                self.last_core_result = result
                if self._detection_sink is not None:
                    for detection in result.detection_events:
                        self._detection_sink(DetectionEventGenerator.to_dict(detection))
        return tracked_event

    def process_packet(
        self,
        packet,
        packet_id: int,
    ) -> dict | None:
        """
        Parse a raw packet and continue through the IDS pipeline.
        """

        event = process_packet(
            packet,
            packet_id,
        )

        return self.process_event(
            event
        )
