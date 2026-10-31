"""Define interfaces for Core Engine components."""

from pathlib import Path
from typing import Iterable, Protocol, Sequence

from .contracts import FlowContext, NormalizedEvent
from .models import (
    CoreEngineResult,
    DetectionEvent,
    EvaluationResult,
    EvaluationStatistics,
    InternalRule,
    MatchResult,
    RuleText,
    RuleValidationResult,
)


class RuleLoader(Protocol):
    def load(self, paths: Sequence[Path]) -> Iterable[RuleText]:
        """Read enabled rule files and preserve source locations."""
        ...

    def is_rule_enabled(self, rule: InternalRule) -> bool:
        """Check whether a validated rule is enabled."""
        ...


class RuleParserValidator(Protocol):
    def parse(self, source: RuleText) -> RuleValidationResult:
        """Validate a rule and return its status."""
        ...


class RuleRepository(Protocol):
    def add(self, rule: InternalRule) -> None:
        """Store a validated rule."""
        ...

    def candidates(self, normalized_event: NormalizedEvent) -> Sequence[InternalRule]:
        """Select indexed candidates that may still fail header matching."""
        ...

    def header_matches(self, normalized_event: NormalizedEvent) -> Sequence[InternalRule]:
        """Select rules satisfying the complete header without evaluating options."""
        ...


class RuleMatchingEngine(Protocol):
    def match(
        self,
        rule: InternalRule,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
    ) -> MatchResult:
        """Evaluate one rule against event and flow data."""
        ...


class RuleEvaluationEngine(Protocol):
    @property
    def statistics(self) -> EvaluationStatistics:
        """Read cumulative counters without changing engine state."""
        ...

    def evaluate(
        self,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
    ) -> EvaluationResult:
        """Evaluate all candidate rules for an event."""
        ...


class DetectionEventGenerator(Protocol):
    def generate(
        self,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
        match_result: MatchResult,
    ) -> DetectionEvent:
        """Build a detection event for a confirmed match."""
        ...


class CoreEngine(Protocol):
    def process(
        self,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
    ) -> CoreEngineResult:
        """Evaluate an event and return match and detection results."""
        ...
