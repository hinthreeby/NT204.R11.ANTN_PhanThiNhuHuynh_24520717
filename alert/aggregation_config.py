from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AggregationConfig:
    """Configure future event-time aggregation; does not activate an engine.

    window_seconds must be a positive integer, even when disabled.
    """

    enabled: bool = False
    window_seconds: int = 60

    def __post_init__(self) -> None:
        if type(self.enabled) is not bool:
            raise ValueError("enabled must be a boolean")
        if type(self.window_seconds) is not int or self.window_seconds <= 0:
            raise ValueError("window_seconds must be a positive integer")
