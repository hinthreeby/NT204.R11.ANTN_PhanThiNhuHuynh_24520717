"""Match current packet TCP flags and transport payload size."""

import re
from typing import Literal

from .contracts import NormalizedEvent
from .models import InternalRule, MatchResult


_FLAGS = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "C": "CWR", "E": "ECE",
}


def _payload_size(transport: dict) -> tuple[int | None, str | None]:
    """Read payload length and reject conflicting raw byte evidence."""

    size = transport.get("payload_length")
    if "payload_length" in transport and (type(size) is not int or size < 0):
        return None, "Invalid transport.payload_length"
    if "payload_hex" in transport:
        raw = transport["payload_hex"]
        if not isinstance(raw, str):
            return None, "Invalid transport.payload_hex"
        try:
            raw_size = len(bytes.fromhex(raw))
        except ValueError:
            return None, "Invalid transport.payload_hex"
        if size is not None and size != raw_size:
            return None, "transport.payload_length conflicts with payload_hex byte length"
        size = raw_size if size is None else size
    if size is None:
        return None, "Missing transport payload size"
    return size, None


def _flags_match(value: str, transport: dict) -> bool:
    flags = transport.get("flags")
    if transport.get("protocol") != "TCP" or not isinstance(flags, list):
        return False
    if not all(isinstance(flag, str) for flag in flags):
        return False
    actual = {flag.upper() for flag in flags}
    if len(actual) != len(flags) or not actual <= set(_FLAGS.values()):
        return False
    if value == "0":
        return not actual
    if not value or any(flag not in _FLAGS for flag in value):
        return False
    return actual == {_FLAGS[flag] for flag in value}


def _dsize_matches(value: str, size: int) -> bool:
    bounds = re.fullmatch(r"([0-9]+)<>([0-9]+)", value)
    if bounds:
        # Both range boundaries are excluded in this supported subset.
        return int(bounds[1]) < size < int(bounds[2])
    comparison = re.fullmatch(r"([<>]?)([0-9]+)", value)
    if comparison is None:
        return False
    operator, number = comparison[1], int(comparison[2])
    if operator == "<":
        return size < number
    if operator == ">":
        return size > number
    return size == number


class PacketMatcher:
    def match(self, rule: InternalRule, normalized_event: NormalizedEvent) -> Literal["MATCH", "NO_MATCH"]:
        """Check packet options without evaluating other rule conditions."""

        if not isinstance(rule, InternalRule):
            return "NO_MATCH"
        return self.evaluate(rule, normalized_event).status

    def evaluate(self, rule: InternalRule, normalized_event: NormalizedEvent) -> MatchResult:
        """Return the packet-option result with a diagnostic reason."""

        if not isinstance(rule, InternalRule):
            raise TypeError("Expected a validated InternalRule")

        def result(status, reason):
            return MatchResult(rule, status, (), reason)

        options = [option for option in rule.options if option.name in {"flags", "dsize"}]
        if not options:
            return result("MATCH", "No packet options to evaluate")
        if not isinstance(normalized_event, dict):
            return result("NO_MATCH", "Missing normalized event")
        if normalized_event.get("processing_action") == "skip" or normalized_event.get("preprocess_status") == "invalid":
            return result("NO_MATCH", "Event is invalid or skipped")
        transport = normalized_event.get("transport")
        if not isinstance(transport, dict):
            return result("NO_MATCH", "Missing transport fields")
        if rule.header.protocol not in ("tcp", "udp") or transport.get("protocol") != rule.header.protocol.upper():
            return result("NO_MATCH", "Transport protocol does not match the validated rule")
        for option in options:
            if not isinstance(option.value, str):
                return result("NO_MATCH", "Missing packet option value")
            if option.name == "flags":
                if not _flags_match(option.value, transport):
                    return result("NO_MATCH", "TCP flags are missing, malformed or not an exact match")
            else:
                size, reason = _payload_size(transport)
                if reason is not None:
                    return result("NO_MATCH", reason)
                if not _dsize_matches(option.value, size):
                    return result("NO_MATCH", "Transport payload size does not satisfy dsize")
        return result("MATCH", "All packet options satisfied; other rule conditions are not evaluated")
