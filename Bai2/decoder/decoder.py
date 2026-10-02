from copy import deepcopy

from config import Bai2Config


class Decoder:
    """
    Decode encoded or represented application data.

    Actual HTTP and SMTP decoding logic will be implemented
    in later development stages.
    """

    def __init__(
        self,
        config: Bai2Config,
    ) -> None:
        self.config = config

    def process(
        self,
        event: dict,
    ) -> dict:
        """
        Process one normalized event.

        Day 1 only forwards a copy of the event.
        """

        return deepcopy(event)