from config import Bai2Config
from decoder.decoder import Decoder
from flow.flow_tracker import FlowTracker
from preprocessor.preprocessor import Preprocessor


class Bai2Pipeline:
    """
    Coordinate Decoder, Preprocessor, and Flow Tracker.
    """

    def __init__(
        self,
        config: Bai2Config | None = None,
    ) -> None:
        if config is None:
            config = Bai2Config()

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
        Process one normalized event through the Bai2 pipeline.
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

            tracked_event = (
                self.flow_tracker.process(
                    preprocessed_event
                )
            )

            return tracked_event

        except Exception as exc:
            print(
                "[ERROR] Bai2 pipeline failed: "
                f"{type(exc).__name__}: {exc}"
            )

            return None