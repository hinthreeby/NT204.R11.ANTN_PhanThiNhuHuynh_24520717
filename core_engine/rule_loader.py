"""Load rule text from files without parsing Snort syntax."""

from dataclasses import dataclass, field
import logging
from pathlib import Path
from typing import Mapping, Sequence

from .models import InternalRule, RuleText


logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RuleLoaderConfig:
    """
    Configure file and rule enablement.
    """

    file_enabled: Mapping[Path, bool] = field(default_factory=dict)
    rule_enabled: Mapping[int, bool] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuleLoadIssue:
    """Describe a rule loading error."""

    source: str
    line_number: int | None
    reason: str


class RuleLoader:
    def __init__(self, config: RuleLoaderConfig | None = None) -> None:
        config = config if config is not None else RuleLoaderConfig()
        self._file_enabled = {
            Path(path).resolve(): enabled
            for path, enabled in config.file_enabled.items()
        }
        self._rule_enabled = dict(config.rule_enabled)
        self.issues: list[RuleLoadIssue] = []

    def _report(self, path: Path, line_number: int | None, reason: str) -> None:
        issue = RuleLoadIssue(str(path), line_number, reason)
        self.issues.append(issue)
        location = f"{path}:{line_number}" if line_number is not None else str(path)
        logger.warning("Rule load error at %s: %s", location, reason)

    def load(self, paths: Sequence[Path]) -> list[RuleText]:
        """
        Read enabled rule files and preserve source locations.
        """

        self.issues.clear()
        rules: list[RuleText] = []
        for configured_path in paths:
            path = Path(configured_path)
            try:
                path = path.resolve()
                if not self._file_enabled.get(path, True):
                    continue
                with path.open("rb") as source:
                    for line_number, raw_line in enumerate(source, start=1):
                        try:
                            encoding = "utf-8-sig" if line_number == 1 else "utf-8"
                            text = raw_line.decode(encoding)
                        except UnicodeDecodeError as exc:
                            self._report(path, line_number, f"Invalid UTF-8: {exc}")
                            continue
                        text = text.removesuffix("\n").removesuffix("\r")
                        if not text.strip() or text.lstrip().startswith("#"):
                            continue
                        rules.append(RuleText(text, str(path), line_number))
            except (OSError, ValueError) as exc:
                self._report(path, None, f"{type(exc).__name__}: {exc}")
        return rules

    def is_rule_enabled(self, rule: InternalRule) -> bool:
        """
        Check whether a validated rule is enabled.
        """

        return self._rule_enabled.get(rule.sid, True)
