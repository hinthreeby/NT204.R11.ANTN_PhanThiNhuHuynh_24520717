from copy import deepcopy

from config import IDSConfig


class FlowTracker:
    """
    Track bidirectional network flows and connection state.

    Actual flow tracking logic will be implemented later.
    """

    def __init__(
        self,
        config: IDSConfig,
    ) -> None:
        self.config = config

        self.active_flows = {}

    def process(
        self,
        event: dict,
    ) -> dict:
        """
        Process one preprocessed event.

        Day 1 only forwards a copy of the event.
        """

        return deepcopy(event)