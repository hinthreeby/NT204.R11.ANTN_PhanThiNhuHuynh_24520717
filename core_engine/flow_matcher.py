"""Match flow direction and TCP connection state options."""

from typing import Literal

from .contracts import FlowContext, NormalizedEvent
from .flow_context_adapter import _flow_endpoints
from .models import InternalRule


class FlowMatcher:
    def match(
        self,
        rule: InternalRule,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
    ) -> Literal["MATCH", "NO_MATCH"]:
        """Check all flow terms without evaluating other rule conditions."""

        options = [option for option in rule.options if option.name == "flow"]
        if not options:
            return "MATCH"
        if _flow_endpoints(normalized_event, flow_context) is None:
            return "NO_MATCH"
        for option in options:
            if not isinstance(option.value, str):
                return "NO_MATCH"
            for term in option.value.split(","):
                term = term.strip()
                if term in ("to_server", "to_client"):
                    if flow_context.get("client_server_direction") != term:
                        return "NO_MATCH"
                elif term == "established":
                    if flow_context.get("state") != "ESTABLISHED":
                        return "NO_MATCH"
                elif term == "not_established":
                    if flow_context.get("state") not in ("NEW", "HANDSHAKE"):
                        return "NO_MATCH"
                else:
                    return "NO_MATCH"
        return "MATCH"
