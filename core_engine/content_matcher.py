"""Match compiled content patterns against raw transport bytes."""

import re
from typing import Iterator, Literal

from .content_pattern import ContentPattern, compile_content_patterns
from .contracts import NormalizedEvent
from .models import InternalRule, MatchInformation, MatchResult


def iter_content_matches(
    pattern: ContentPattern,
    payload: bytes,
    previous_end: int | None = None,
) -> Iterator[MatchInformation]:
    """Yield byte occurrences inside an absolute or relative window."""

    if not pattern.pattern:
        raise ValueError("Content pattern must not be empty")
    bounds = {}
    for option in pattern.modifiers:
        if option.name in {"offset", "depth", "distance", "within"}:
            value = option.value
            numeric = r"-?[0-9]+" if option.name == "distance" else r"[0-9]+"
            if (
                not isinstance(value, str) or re.fullmatch(numeric, value) is None
                or (option.name in {"depth", "within"} and int(value) < 1)
            ):
                raise ValueError(f"Invalid {option.name} value for content option {pattern.option_index}")
            bounds[option.name] = int(value)
    relative = bool(bounds.keys() & {"distance", "within"})
    if relative:
        if bounds.keys() & {"offset", "depth"}:
            raise ValueError("Cannot combine absolute and relative content modifiers")
        if type(previous_end) is not int or not 0 <= previous_end <= len(payload):
            raise ValueError("Relative content requires a previous match end")
        window_start = previous_end + bounds.get("distance", 0)
        window_end = window_start + bounds["within"] if "within" in bounds else len(payload)
    else:
        window_start = bounds.get("offset", 0)
        window_end = window_start + bounds.get("depth", len(payload))
    window_start, window_end = max(0, window_start), min(len(payload), window_end)
    if window_end <= window_start:
        return
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
        if any(option.name in {"distance", "within"} for pattern in patterns for option in pattern.modifiers):
            states: dict[int | None, tuple[MatchInformation, ...]] = {None: ()}
            for pattern in patterns:
                next_states = {}
                for previous_end, path in states.items():
                    try:
                        for occurrence in iter_content_matches(pattern, payload, previous_end):
                            # Future relative conditions depend only on this end cursor.
                            next_states.setdefault(occurrence.end, path + (occurrence,))
                    except ValueError as exc:
                        return MatchResult(rule, "NO_MATCH", (), str(exc))
                if not next_states:
                    return MatchResult(rule, "NO_MATCH", (), f"No compatible content chain at option {pattern.option_index}")
                states = next_states
            return MatchResult(rule, "MATCH", next(iter(states.values())), "A complete content chain satisfied; other rule conditions are not evaluated")
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
