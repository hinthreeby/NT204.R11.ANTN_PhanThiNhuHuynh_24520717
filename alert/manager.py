from .models import Alert, AlertResult
from .severity import SeverityConfig
from .validation import DetectionValidationError, validate_detection_event


class AlertManager:
    def __init__(self, config: SeverityConfig | None = None) -> None:
        self.config = config if config is not None else SeverityConfig()
        if not isinstance(self.config, SeverityConfig):
            raise TypeError("Expected SeverityConfig")

    def process(self, detection_event: object) -> AlertResult:
        """Create one alert or reject source data with a specific reason."""

        try:
            fields = validate_detection_event(detection_event)
        except DetectionValidationError as exc:
            return AlertResult("rejected", None, str(exc))
        alert = Alert(
            **fields,
            severity=self.config.severity_for(fields["priority"]),
            first_seen=fields["timestamp"],
            last_seen=fields["timestamp"],
        )
        return AlertResult("created", alert, None)
