"""Match compiled content patterns against raw transport bytes."""

from typing import Iterator, Literal

from .content_pattern import ContentPattern, compile_content_patterns
from .contracts import NormalizedEvent
from .models import InternalRule, MatchInformation, MatchResult


def iter_content_matches(pattern: ContentPattern, payload: bytes) -> Iterator[MatchInformation]:
    """Yield every byte occurrence inside the absolute search window."""

    if not pattern.pattern:
        raise ValueError("Content pattern must not be empty")
    bounds = {"offset": 0, "depth": len(payload)}
    for option in pattern.modifiers:
        if option.name in bounds:
            value = option.value
            if (
                not isinstance(value, str) or not value.isascii() or not value.isdecimal()
                or int(value) < (1 if option.name == "depth" else 0)
            ):
                raise ValueError(f"Invalid {option.name} value for content option {pattern.option_index}")
            bounds[option.name] = int(value)
    window_start = bounds["offset"]
    window_end = min(len(payload), window_start + bounds["depth"])
    buffer = payload.lower() if pattern.nocase else payload
    needle = pattern.pattern.lower() if pattern.nocase else pattern.pattern
    start = buffer.find(needle, window_start, window_end)
    while start >= 0:
        end = start + len(needle)
        yield MatchInformation(
            field="transport.payload_hex",
            start=start,
            end=end,
            matched_hex=payload[start:end].hex(),
            option_index=pattern.option_index,
        )
        start = buffer.find(needle, start + 1, window_end)


class ContentMatcher:
    def match(self, rule: InternalRule, normalized_event: NormalizedEvent) -> Literal["MATCH", "NO_MATCH"]:
        """Check content conditions without evaluating the whole rule."""

        if not isinstance(rule, InternalRule):
            return "NO_MATCH"
        return self.evaluate(rule, normalized_event).status

    def evaluate(self, rule: InternalRule, normalized_event: NormalizedEvent) -> MatchResult:
        """Return content status, byte occurrences and a diagnostic reason."""

        if not isinstance(rule, InternalRule):
            raise TypeError("Expected a validated InternalRule")
        try:
            patterns = compile_content_patterns(rule)
        except ValueError as exc:
            return MatchResult(rule, "NO_MATCH", (), f"Content compilation failed: {exc}")
        if not patterns:
            return MatchResult(rule, "MATCH", (), "No content conditions; other rule conditions are not evaluated")
        positional = sorted({
            option.name for pattern in patterns for option in pattern.modifiers
            if option.name in {"distance", "within"}
        })
        if positional:
            return MatchResult(rule, "NO_MATCH", (), "Content evaluation is inconclusive; positional modifiers not implemented: " + ", ".join(positional))
        if not isinstance(normalized_event, dict):
            return MatchResult(rule, "NO_MATCH", (), "Missing normalized event")
        if normalized_event.get("processing_action") == "skip" or normalized_event.get("preprocess_status") == "invalid":
            return MatchResult(rule, "NO_MATCH", (), "Event is invalid or skipped")
        transport = normalized_event.get("transport")
        if not isinstance(transport, dict):
            return MatchResult(rule, "NO_MATCH", (), "Missing transport fields")
        if rule.header.protocol not in ("tcp", "udp") or transport.get("protocol") != rule.header.protocol.upper():
            return MatchResult(rule, "NO_MATCH", (), "Transport protocol does not match the validated rule")
        raw = transport.get("payload_hex")
        if not isinstance(raw, str):
            return MatchResult(rule, "NO_MATCH", (), "Missing or invalid transport.payload_hex")
        try:
            payload = bytes.fromhex(raw)
        except ValueError:
            return MatchResult(rule, "NO_MATCH", (), "Invalid transport.payload_hex")
        if "payload_length" in transport:
            size = transport["payload_length"]
            if type(size) is not int or size < 0 or size != len(payload):
                return MatchResult(rule, "NO_MATCH", (), "transport.payload_length is invalid or conflicts with raw bytes")
        information = []
        for pattern in patterns:
            try:
                occurrences = tuple(iter_content_matches(pattern, payload))
            except ValueError as exc:
                return MatchResult(rule, "NO_MATCH", tuple(information), str(exc))
            if not occurrences:
                return MatchResult(rule, "NO_MATCH", tuple(information), f"Content option {pattern.option_index} not found in raw transport payload")
            information.extend(occurrences)
        return MatchResult(rule, "MATCH", tuple(information), "All content conditions satisfied; other rule conditions are not evaluated")
