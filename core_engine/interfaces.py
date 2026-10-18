"""Structural interfaces for future components; no executable implementations.

The planned pipeline boundary is after FlowTracker.process(): pass the tracked
event and its flow metadata. Do not activate it until evaluation is implemented.
Consumers must not mutate input events/contexts. No component imports capture
libraries, prints alerts from the matcher, or assumes forward means to_server.
"""

from pathlib import Path
from typing import Iterable, Protocol, Sequence

from .contracts import FlowContext, NormalizedEvent
from .models import (
    CoreEngineResult,
    DetectionEvent,
    InternalRule,
    MatchResult,
    RuleText,
    RuleValidationResult,
)


class RuleLoader(Protocol):
    def load(self, paths: Sequence[Path]) -> Iterable[RuleText]:
        """Yield enabled rule text with provenance; report individual load errors."""
        ...


class RuleParserValidator(Protocol):
    def parse(self, source: RuleText) -> RuleValidationResult:
        """Classify valid/invalid/unsupported without halting other rules."""
        ...


class RuleRepository(Protocol):
    def add(self, rule: InternalRule) -> None:
        """Store a validated rule; index construction belongs here."""
        ...

    def candidates(self, normalized_event: NormalizedEvent) -> Sequence[InternalRule]:
        """Select candidate rules using header fields."""
        ...


class RuleMatchingEngine(Protocol):
    def match(
        self,
        rule: InternalRule,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
    ) -> MatchResult:
        """Evaluate one rule without generating or printing detection events."""
        ...


class RuleEvaluationEngine(Protocol):
    def evaluate(
        self,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
    ) -> Sequence[MatchResult]:
        """Query candidates and evaluate all; retain results for multiple matches."""
        ...


class DetectionEventGenerator(Protocol):
    def generate(
        self,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
        match_result: MatchResult,
    ) -> DetectionEvent:
        """Build one detection for a confirmed MATCH; never for NO_MATCH."""
        ...


class CoreEngine(Protocol):
    def process(
        self,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
    ) -> CoreEngineResult:
        """Future orchestration of evaluation and detection generation."""
        ...
