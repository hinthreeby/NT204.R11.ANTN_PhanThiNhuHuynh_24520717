"""Match validated rule headers against normalized events."""

from ipaddress import IPv4Address, IPv4Network
from typing import Literal

from .contracts import NormalizedEvent
from .models import RuleHeader


def _endpoint_matches(
    rule_ip: str,
    rule_port: str,
    event_ip: IPv4Address,
    event_port: int,
) -> bool:
    if rule_ip != "any" and event_ip not in IPv4Network(rule_ip, strict=False):
        return False
    if rule_port == "any":
        return True
    if ":" not in rule_port:
        return event_port == int(rule_port)
    lower, upper = rule_port.split(":")
    return (int(lower) if lower else 0) <= event_port <= (int(upper) if upper else 65535)


class HeaderMatcher:
    def match(
        self,
        header: RuleHeader,
        normalized_event: NormalizedEvent,
    ) -> Literal["MATCH", "NO_MATCH"]:
        """
        Check protocol and endpoints without evaluating rule options.
        """

        if header.action != "alert" or header.protocol not in {"tcp", "udp"}:
            return "NO_MATCH"
        if header.direction not in {"->", "<>"}:
            return "NO_MATCH"
        if not isinstance(normalized_event, dict):
            return "NO_MATCH"
        network = normalized_event.get("network")
        transport = normalized_event.get("transport")
        if not isinstance(network, dict) or not isinstance(transport, dict):
            return "NO_MATCH"
        if transport.get("protocol") != header.protocol.upper():
            return "NO_MATCH"

        src_port = transport.get("src_port")
        dst_port = transport.get("dst_port")
        if any(type(port) is not int or not 0 <= port <= 65535 for port in (src_port, dst_port)):
            return "NO_MATCH"
        src_ip = network.get("src_ip")
        dst_ip = network.get("dst_ip")
        if not isinstance(src_ip, str) or not isinstance(dst_ip, str):
            return "NO_MATCH"
        try:
            source = (IPv4Address(src_ip), src_port)
            destination = (IPv4Address(dst_ip), dst_port)
        except ValueError:
            return "NO_MATCH"

        if (
            _endpoint_matches(header.src_ip, header.src_port, *source)
            and _endpoint_matches(header.dst_ip, header.dst_port, *destination)
        ):
            return "MATCH"
        # Reverse complete endpoints, including both IP and port.
        if header.direction == "<>" and (
            _endpoint_matches(header.src_ip, header.src_port, *destination)
            and _endpoint_matches(header.dst_ip, header.dst_port, *source)
        ):
            return "MATCH"
        return "NO_MATCH"
