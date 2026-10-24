"""Store validated and enabled internal rules."""

import logging
from pathlib import Path
from typing import Sequence

from .interfaces import RuleLoader, RuleParserValidator
from .models import InternalRule, RuleValidationResult


logger = logging.getLogger(__name__)


class RuleRepository:
    def __init__(self, loader: RuleLoader | None = None) -> None:
        self._loader = loader
        self._rules: dict[int, InternalRule] = {}

    @property
    def active_rules(self) -> tuple[InternalRule, ...]:
        """Return active rules in insertion order."""

        return tuple(self._rules.values())

    def get(self, sid: int) -> InternalRule | None:
        """Find an active rule by SID."""

        return self._rules.get(sid)

    def add(self, rule: InternalRule) -> None:
        """Store an already validated rule if it is enabled."""

        if not isinstance(rule, InternalRule):
            raise TypeError("Expected a validated InternalRule")
        if self._loader is not None and not self._loader.is_rule_enabled(rule):
            return
        if rule.sid in self._rules:
            logger.warning("Duplicate SID %s ignored; keeping the first active rule", rule.sid)
            return
        self._rules[rule.sid] = rule

    def add_validated(self, result: RuleValidationResult) -> None:
        """Accept only valid results containing an internal rule."""

        if result.status == "valid" and isinstance(result.rule, InternalRule):
            self.add(result.rule)

    def rebuild(
        self,
        paths: Sequence[Path],
        loader: RuleLoader,
        parser: RuleParserValidator,
    ) -> None:
        """Replace active rules using the current loader and validator."""

        replacement = RuleRepository(loader)
        for source in loader.load(paths):
            replacement.add_validated(parser.parse(source))
        self._loader = loader
        self._rules = replacement._rules
