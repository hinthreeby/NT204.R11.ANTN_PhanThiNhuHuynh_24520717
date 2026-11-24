from .aggregation import AlertAggregator
from .aggregation_config import AggregationConfig
from .filtering import AlertFilterConfig, filter_detection
from .models import Alert, AlertGroup, AlertResult
from .severity import SeverityConfig
from .validation import DetectionValidationError, validate_detection_event


class AlertManager:
    def __init__(
        self,
        config: SeverityConfig | None = None,
        *,
        filter_config: AlertFilterConfig | None = None,
        aggregation_config: AggregationConfig | None = None,
    ) -> None:
        self.config = config if config is not None else SeverityConfig()
        if not isinstance(self.config, SeverityConfig):
            raise TypeError("Expected SeverityConfig")
        self.filter_config = filter_config if filter_config is not None else AlertFilterConfig()
        if not isinstance(self.filter_config, AlertFilterConfig):
            raise TypeError("Expected AlertFilterConfig")
        self._aggregator = AlertAggregator(aggregation_config)

    @property
    def aggregation_config(self) -> AggregationConfig:
        """Read the fixed aggregation policy for this manager's stream."""
        return self._aggregator.config

    def process(self, detection_event: object) -> AlertResult:
        """Validate, map severity and filter before optional aggregation.

        Blocked input never reaches the engine or advances its watermark.
        AggregationCapacityError propagates without changing engine state;
        callers can consume flush() output and retry the detection.
        """

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
        if not self.aggregation_config.enabled:
            return AlertResult("created", alert, None)
        result = self._aggregator.process(alert)
        status = {"created": "created", "merged": "aggregated", "late": "finalized"}[result.status]
        return AlertResult(status, result.group.summary, None,
                           group=result.group, finalized=result.finalized)

    def flush(self) -> tuple[AlertGroup, ...]:
        """Return and remove open groups for finalization by the caller.

        Empty when disabled or already flushed. The engine retains its event-time
        watermark; create a new manager for an unrelated stream. Output delivery
        and persistence belong to the caller, with no internal finalized queue.
        """
        return self._aggregator.flush()
