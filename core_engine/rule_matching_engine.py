"""Coordinate existing matchers for one validated rule."""

from .content_matcher import ContentMatcher
from .contracts import FlowContext, NormalizedEvent
from .flow_matcher import FlowMatcher
from .header_matcher import HeaderMatcher
from .models import InternalRule, MatchInformation, MatchResult
from .packet_matcher import PacketMatcher


class RuleMatchingEngine:
    def __init__(self) -> None:
        self._header = HeaderMatcher()
        self._flow = FlowMatcher()
        self._packet = PacketMatcher()
        self._content = ContentMatcher()

    def match(
        self,
        rule: InternalRule,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
    ) -> MatchResult:
        """Evaluate all conditions of an already validated rule."""

        if not isinstance(rule, InternalRule):
            raise TypeError("Expected a validated InternalRule")
        if not isinstance(normalized_event, dict):
            return MatchResult(rule, "NO_MATCH", (), "Missing normalized event")
        if normalized_event.get("processing_action") == "skip" or normalized_event.get("preprocess_status") == "invalid":
            return MatchResult(rule, "NO_MATCH", (), "Event is invalid or skipped")
        if self._header.match(rule.header, normalized_event) != "MATCH":
            return MatchResult(rule, "NO_MATCH", (), "Header conditions not satisfied")
        if self._flow.match(rule, normalized_event, flow_context) != "MATCH":
            return MatchResult(rule, "NO_MATCH", (), "Flow conditions not satisfied or context unavailable")
        packet_result = self._packet.evaluate(rule, normalized_event)
        if packet_result.status != "MATCH":
            return MatchResult(rule, "NO_MATCH", (), packet_result.reason)
        content_result = self._content.evaluate(rule, normalized_event)
        if content_result.status != "MATCH":
            return MatchResult(rule, "NO_MATCH", (), content_result.reason)

        information = [
            MatchInformation(field=field)
            for field in (
                "transport.protocol", "network.src_ip", "transport.src_port",
                "network.dst_ip", "transport.dst_port",
            )
        ]
        for index, option in enumerate(rule.options):
            if option.name == "flow":
                for term in option.value.split(","):
                    field = "client_server_direction" if term.strip() in {"to_server", "to_client"} else "state"
                    information.append(MatchInformation(field=f"flow.{field}", option_index=index))
            elif option.name in {"flags", "dsize"}:
                field = "flags" if option.name == "flags" else "payload_length"
                information.append(MatchInformation(field=f"transport.{field}", option_index=index))
        information.extend(packet_result.information)
        information.extend(content_result.information)
        return MatchResult(rule, "MATCH", tuple(information), "All rule conditions satisfied")
