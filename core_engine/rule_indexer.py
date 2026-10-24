"""Select possible rules using protocol and port buckets."""

from .contracts import NormalizedEvent
from .models import InternalRule


class RuleIndexer:
    def __init__(self) -> None:
        self._forward: dict[tuple[str, int | None], dict[int, InternalRule]] = {}
        self._reverse: dict[tuple[str, int | None], dict[int, InternalRule]] = {}
        self._order: dict[int, int] = {}

    def add(self, rule: InternalRule) -> None:
        """Index one active validated rule without changing it."""

        if rule.sid in self._order:
            return
        self._order[rule.sid] = len(self._order)
        selector = rule.header.dst_port
        # Keep any and ranges for exact checking by HeaderMatcher.
        port = int(selector) if selector.isdecimal() else None
        key = (rule.header.protocol.upper(), port)
        self._forward.setdefault(key, {})[rule.sid] = rule
        if rule.header.direction == "<>":
            self._reverse.setdefault(key, {})[rule.sid] = rule

    def candidates(self, normalized_event: NormalizedEvent) -> tuple[InternalRule, ...]:
        """Return indexed candidates without claiming a header match."""

        if not isinstance(normalized_event, dict):
            return ()
        transport = normalized_event.get("transport")
        if not isinstance(transport, dict):
            return ()
        protocol = transport.get("protocol")
        if not isinstance(protocol, str) or protocol not in {"TCP", "UDP"}:
            return ()
        src_port = transport.get("src_port")
        dst_port = transport.get("dst_port")
        if any(type(port) is not int or not 0 <= port <= 65535 for port in (src_port, dst_port)):
            return ()

        selected: dict[int, InternalRule] = {}
        for buckets, port in ((self._forward, dst_port), (self._reverse, src_port)):
            selected.update(buckets.get((protocol, None), {}))
            selected.update(buckets.get((protocol, port), {}))
        return tuple(sorted(selected.values(), key=lambda rule: self._order[rule.sid]))
