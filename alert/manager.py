from .filtering import AlertFilterConfig, filter_detection
from .models import Alert, AlertResult
from .severity import SeverityConfig
from .validation import DetectionValidationError, validate_detection_event


class AlertManager:
    def __init__(
        self,
        config: SeverityConfig | None = None,
        *,
        filter_config: AlertFilterConfig | None = None,
    ) -> None:
        self.config = config if config is not None else SeverityConfig()
        if not isinstance(self.config, SeverityConfig):
            raise TypeError("Expected SeverityConfig")
        self.filter_config = filter_config if filter_config is not None else AlertFilterConfig()
        if not isinstance(self.filter_config, AlertFilterConfig):
            raise TypeError("Expected AlertFilterConfig")

    def process(self, detection_event: object) -> AlertResult:
        """Validate and filter a detection before creating an independent alert."""

        try:
            fields = validate_detection_event(detection_event)
        except DetectionValidationError as exc:
            return AlertResult("rejected", None, str(exc))
        severity = self.config.severity_for(fields["priority"])
        decision = filter_detection(fields, severity, self.filter_config)
        if decision is not None:
            return decision
        alert = Alert(
            **fields,
            severity=severity,
            first_seen=fields["timestamp"],
            last_seen=fields["timestamp"],
        )
        return AlertResult("created", alert, None)
