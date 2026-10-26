"""Enrich flow context using observed TCP initiator evidence."""

from copy import deepcopy
from ipaddress import IPv4Address

from .contracts import FlowContext, NormalizedEvent


def _endpoint(ip, port) -> tuple[str, int] | None:
    if not isinstance(ip, str) or type(port) is not int or not 0 <= port <= 65535:
        return None
    try:
        return str(IPv4Address(ip)), port
    except ValueError:
        return None


def _flow_endpoints(event: NormalizedEvent, context: FlowContext | None) -> tuple | None:
    """Check packet membership in a tracked TCP flow."""

    if not isinstance(event, dict) or not isinstance(context, dict):
        return None
    if context.get("tracked") is not True or context.get("protocol") != "TCP":
        return None
    flow_id = context.get("flow_id")
    if not isinstance(flow_id, str) or not flow_id:
        return None
    if event.get("processing_action") == "skip" or event.get("preprocess_status") == "invalid":
        return None
    network, transport = event.get("network"), event.get("transport")
    a, b = context.get("endpoint_a"), context.get("endpoint_b")
    if not all(isinstance(value, dict) for value in (network, transport, a, b)):
        return None
    if transport.get("protocol") != "TCP":
        return None
    embedded = event.get("flow")
    if isinstance(embedded, dict) and embedded.get("flow_id") != flow_id:
        return None
    source = _endpoint(network.get("src_ip"), transport.get("src_port"))
    destination = _endpoint(network.get("dst_ip"), transport.get("dst_port"))
    first, second = _endpoint(a.get("ip"), a.get("port")), _endpoint(b.get("ip"), b.get("port"))
    if any(value is None for value in (source, destination, first, second)):
        return None
    if first == second or (source, destination) not in ((first, second), (second, first)):
        return None
    return source, destination


class FlowContextAdapter:
    def __init__(self) -> None:
        self._roles: dict[str, tuple[tuple[str, int], tuple[str, int]] | None] = {}

    def forget(self, flow_id: str) -> None:
        """Discard evidence for a retired flow instance."""

        self._roles.pop(flow_id, None)

    def clear(self) -> None:
        """Discard evidence before processing an independent capture."""

        self._roles.clear()

    def enrich(self, event: NormalizedEvent, flow_context: FlowContext | None) -> FlowContext:
        """Return copied context with an evidence-based packet direction."""

        context = deepcopy(flow_context) if isinstance(flow_context, dict) else {}
        context["client_server_direction"] = "UNKNOWN"
        if isinstance(event, dict):
            expired = event.get("expired_flows")
            if isinstance(expired, list):
                for summary in expired:
                    if isinstance(summary, dict) and isinstance(summary.get("flow_id"), str):
                        self.forget(summary["flow_id"])
        endpoints = _flow_endpoints(event, context)
        if endpoints is None:
            return context
        flow_id = context["flow_id"]
        flags = event["transport"].get("flags")
        if isinstance(flags, list) and all(isinstance(flag, str) for flag in flags):
            observed = set(flags)
            if (
                "SYN" in observed and not observed.intersection({"ACK", "FIN", "RST"})
                and context.get("state") == "HANDSHAKE"
            ):
                if flow_id not in self._roles:
                    self._roles[flow_id] = endpoints
                elif self._roles[flow_id] != endpoints:
                    # Opposite initiators provide no unique client/server role.
                    self._roles[flow_id] = None
        roles = self._roles.get(flow_id)
        if roles is not None:
            if endpoints == roles:
                context["client_server_direction"] = "to_server"
            elif endpoints == roles[::-1]:
                context["client_server_direction"] = "to_client"
        if context.get("state") in ("CLOSED", "RESET"):
            self.forget(flow_id)
        return context
