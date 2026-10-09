from config import IDSConfig

from decoder.decoder import Decoder
from flow.flow_tracker import FlowTracker
from parsers.packet_parser import process_packet
from preprocessor.preprocessor import Preprocessor


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

    def process_event(
        self,
        event: dict,
    ) -> dict | None:
        """
        Process one normalized IDS event.
        """

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

            return tracked_event

        except Exception as exc:
            print(
                "[ERROR] IDS pipeline failed: "
                f"{type(exc).__name__}: {exc}"
            )

            return None

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