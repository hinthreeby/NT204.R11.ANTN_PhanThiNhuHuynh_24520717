from copy import deepcopy

from config import IDSConfig


class Preprocessor:
    """
    Validate and normalize decoded IDS events.

    Actual validation and normalization rules will be
    implemented later.
    """

    def __init__(
        self,
        config: IDSConfig,
    ) -> None:
        self.config = config

    def process(
        self,
        event: dict,
    ) -> dict:
        """
        Process one decoded event.

        Day 1 only forwards a copy of the event.
        """

        return deepcopy(event)