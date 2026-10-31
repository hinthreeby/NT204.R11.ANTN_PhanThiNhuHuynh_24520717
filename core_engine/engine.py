"""Connect rule loading, evaluation and detection generation."""

import logging
from pathlib import Path
from typing import Sequence

from .contracts import FlowContext, NormalizedEvent
from .detection_event import DetectionEventGenerator
from .evaluation_engine import RuleEvaluationEngine
from .flow_context_adapter import FlowContextAdapter
from .models import CoreEngineResult, EvaluationStatistics
from .rule_loader import RuleLoader, RuleLoaderConfig
from .rule_parser import RuleParserValidator
from .rule_repository import RuleRepository


logger = logging.getLogger(__name__)


class CoreEngine:
    def __init__(self, repository: RuleRepository) -> None:
        self._adapter = FlowContextAdapter()
        self._evaluation = RuleEvaluationEngine(repository)
        self._generator = DetectionEventGenerator()

    @classmethod
    def from_rule_files(
        cls,
        paths: Sequence[Path],
        loader_config: RuleLoaderConfig | None = None,
    ) -> "CoreEngine":
        """Load enabled rules once and report rejected source lines."""

        loader, parser = RuleLoader(loader_config), RuleParserValidator()
        repository = RuleRepository(loader)
        for source in loader.load(paths):
            result = parser.parse(source)
            if result.status != "valid":
                logger.warning("Rule %s:%s %s: %s", source.source, source.line_number, result.status, result.reason)
            repository.add_validated(result)
        return cls(repository)

    @property
    def statistics(self) -> EvaluationStatistics:
        """Read completed evaluation counters."""

        return self._evaluation.statistics

    def forget_flow(self, flow_id: str) -> None:
        """Remove role evidence for an explicitly expired flow."""

        self._adapter.forget(flow_id)

    def process(
        self,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
    ) -> CoreEngineResult:
        """Observe flow evidence before evaluating all candidate rules."""

        if flow_context is None:
            flow_context = normalized_event.get("flow")
        context = self._adapter.enrich(normalized_event, flow_context)
        evaluation = self._evaluation.evaluate(normalized_event, context)
        detections = self._generator.generate_all(normalized_event, context, evaluation)
        return CoreEngineResult(evaluation.matches, detections)
