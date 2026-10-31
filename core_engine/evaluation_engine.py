"""Evaluate all indexed rule candidates for a normalized event."""

from .contracts import FlowContext, NormalizedEvent
from .interfaces import RuleMatchingEngine as MatchingInterface, RuleRepository
from .models import EvaluationResult, EvaluationStatistics, InternalRule, MatchResult
from .rule_matching_engine import RuleMatchingEngine


class RuleEvaluationEngine:
    def __init__(
        self,
        repository: RuleRepository,
        matcher: MatchingInterface | None = None,
    ) -> None:
        self._repository = repository
        self._matcher = matcher if matcher is not None else RuleMatchingEngine()
        self._statistics = EvaluationStatistics()

    @property
    def statistics(self) -> EvaluationStatistics:
        """Return an immutable snapshot of completed evaluation counters."""

        return self._statistics

    def evaluate(
        self,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
    ) -> EvaluationResult:
        """Collect every matching rule and commit counters after success."""

        if not isinstance(normalized_event, dict):
            raise TypeError("Expected a normalized event dictionary")
        candidates = ()
        if normalized_event.get("processing_action") != "skip" and normalized_event.get("preprocess_status") != "invalid":
            candidates = self._repository.candidates(normalized_event)
        seen: set[InternalRule] = set()
        matches = []
        for rule in candidates:
            if not isinstance(rule, InternalRule):
                raise TypeError("Repository candidate must be a validated InternalRule")
            if rule in seen:
                continue
            seen.add(rule)
            result = self._matcher.match(rule, normalized_event, flow_context)
            if not isinstance(result, MatchResult) or result.rule != rule or result.status not in {"MATCH", "NO_MATCH"}:
                raise ValueError(f"Invalid matching result for rule SID {rule.sid}, rev {rule.rev}")
            if result.status == "MATCH":
                matches.append(result)

        evaluation = EvaluationResult(tuple(matches), len(seen))
        previous = self._statistics
        self._statistics = EvaluationStatistics(
            previous.events_evaluated_total + evaluation.events_evaluated,
            previous.candidate_rules_total + evaluation.candidate_rules,
            previous.matches_total + evaluation.match_count,
        )
        return evaluation
