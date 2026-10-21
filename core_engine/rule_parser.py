"""Parse and validate supported Snort rules."""

from ipaddress import ip_network
import re

from .models import (
    InternalRule,
    RuleHeader,
    RuleOption,
    RuleText,
    RuleValidationResult,
)


class _InvalidRule(ValueError):
    pass


class _UnsupportedRule(ValueError):
    pass


_KEYWORDS = {
    "msg", "sid", "rev", "content", "nocase", "offset", "depth", "distance",
    "within", "flags", "dsize", "flow", "classtype", "priority",
}
_MODIFIERS = {"nocase", "offset", "depth", "distance", "within"}


def _split_rule(text: str) -> tuple[str, list[str]]:
    """Split the rule header and options while respecting quoted content."""

    if not isinstance(text, str) or any(c in text for c in "\x00\r\n"):
        raise _InvalidRule("Expected one text line without NUL/CR/LF")
    opening = text.find("(")
    if opening < 0:
        raise _InvalidRule("Missing parenthesized rule options")
    header = text[:opening].strip()
    if any(c in header for c in '\")'):
        raise _InvalidRule("Unexpected quote or closing parenthesis in header")
    quoted = escaped = False
    start = opening + 1
    options = []
    for index in range(start, len(text)):
        char = text[index]
        if escaped:
            escaped = False
            continue
        if quoted and char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted:
            if char == "(":
                raise _InvalidRule("Nested option parentheses must be quoted")
            if char == ";":
                option = text[start:index].strip()
                if not option:
                    raise _InvalidRule("Empty option between semicolons")
                options.append(option)
                start = index + 1
            elif char == ")":
                if text[start:index].strip():
                    raise _InvalidRule("Each option must end with a semicolon")
                trailing = text[index + 1:].strip()
                if trailing and not trailing.startswith("#"):
                    raise _InvalidRule("Unexpected text after rule options")
                return header, options
    raise _InvalidRule("Unclosed quote/escape or missing closing parenthesis")


def _integer(value: str | None, name: str, minimum: int | None = 0, signed: bool = False) -> int:
    pattern = r"-?[0-9]+" if signed else r"[0-9]+"
    if value is None or re.fullmatch(pattern, value) is None:
        raise _InvalidRule(f"{name} requires a decimal integer")
    number = int(value)
    if minimum is not None and number < minimum:
        raise _InvalidRule(f"{name} must be >= {minimum}")
    return number


def _quoted(value: str | None, name: str) -> str:
    if value is None or len(value) < 2 or value[0] != '"' or value[-1] != '"':
        raise _InvalidRule(f"{name} requires a double-quoted value")
    result = []
    index = 1
    while index < len(value) - 1:
        char = value[index]
        if char == "\\":
            index += 1
            if index >= len(value) - 1 or value[index] not in '\\";:|':
                raise _InvalidRule(f"{name} has an invalid escape")
            char = value[index]
        elif char == '"':
            raise _InvalidRule(f"{name} has an unescaped quote")
        result.append(char)
        index += 1
    return "".join(result)


def _content(value: str | None) -> None:
    decoded = _quoted(value, "content")
    if not decoded:
        raise _InvalidRule("content must not be empty")
    # Inspect the original quoted value so an escaped pipe remains literal.
    index = 1
    while index < len(value) - 1:
        if value[index] == "\\":
            index += 2
        elif value[index] == "|":
            end = value.find("|", index + 1)
            if end < 0:
                raise _InvalidRule("Unclosed content hex block")
            block = value[index + 1:end]
            tokens = block.split()
            if not tokens or any(
                len(token) % 2 or re.fullmatch(r"[0-9a-fA-F]+", token) is None
                for token in tokens
            ):
                raise _InvalidRule("content hex block requires complete hexadecimal bytes")
            index = end + 1
        else:
            index += 1


def _address(value: str) -> None:
    if any(c in value for c in "!$[],"):
        raise _UnsupportedRule("Address variables/lists/negation are unsupported")
    if value == "any":
        return
    if "/" in value and re.fullmatch(r"[0-9]+", value.rsplit("/", 1)[1]) is None:
        raise _InvalidRule("CIDR prefix must be a decimal integer")
    try:
        network = ip_network(value, strict=False)
    except ValueError as exc:
        raise _InvalidRule(f"Invalid IPv4/CIDR: {value}") from exc
    if network.version != 4:
        raise _UnsupportedRule("Only IPv4/CIDR addresses are supported")


def _port(value: str) -> None:
    if any(c in value for c in "!$[],"):
        raise _UnsupportedRule("Port variables/lists/negation are unsupported")
    if value == "any":
        return
    parts = value.split(":")
    if len(parts) > 2:
        raise _InvalidRule(f"Invalid port/range: {value}")
    bounds = []
    for index, part in enumerate(parts):
        if not part and len(parts) == 2:
            number = 0 if index == 0 else 65535
        else:
            number = _integer(part, "port")
        if number > 65535:
            raise _InvalidRule("Port must be in 0..65535")
        bounds.append(number)
    if len(bounds) == 2 and bounds[0] > bounds[1]:
        raise _InvalidRule("Port range is reversed")


def _header(text: str) -> RuleHeader:
    # Keep bracketed selectors together for unsupported syntax reporting.
    fields = re.findall(r"!?\[[^\[\]]*\]|\S+", text)
    if len(fields) != 7:
        raise _InvalidRule("Header requires action protocol src_ip src_port direction dst_ip dst_port")
    action, protocol, src_ip, src_port, direction, dst_ip, dst_port = fields
    if any(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", word) is None for word in (action, protocol)):
        raise _InvalidRule("Action and protocol must be identifiers")
    if action != "alert":
        raise _UnsupportedRule(f"Unsupported action: {action}")
    if protocol not in {"tcp", "udp"}:
        raise _UnsupportedRule(f"Unsupported protocol: {protocol}")
    if direction not in {"->", "<>"}:
        raise _InvalidRule(f"Invalid header direction: {direction}; expected -> or <>")
    _address(src_ip)
    _address(dst_ip)
    _port(src_port)
    _port(dst_port)
    return RuleHeader(action, protocol, src_ip, src_port, direction, dst_ip, dst_port)


def _packet_option(option: RuleOption, protocol: str) -> None:
    value = option.value
    if option.name == "flags":
        if protocol != "tcp":
            raise _InvalidRule("flags requires TCP")
        if value is None or not value:
            raise _InvalidRule("flags requires a value")
        if any(c in value for c in "+*! ,"):
            raise _UnsupportedRule("flags masks/modifiers are not supported by this validator")
        if value != "0" and (
            any(c not in "FSRPAUCE" for c in value) or len(set(value)) != len(value)
        ):
            raise _InvalidRule("Invalid or duplicate TCP flags")
    else:
        if value is None:
            raise _InvalidRule("dsize requires a value")
        if "<>" in value:
            bounds = value.split("<>")
            if len(bounds) != 2 or _integer(bounds[0], "dsize") >= _integer(bounds[1], "dsize"):
                raise _InvalidRule("Invalid dsize range")
        else:
            _integer(value[1:] if value.startswith(("<", ">")) else value, "dsize")


def _options(parts: list[str], protocol: str) -> tuple[RuleOption, ...]:
    options = []
    singleton = set()
    modifiers = None
    content_count = 0
    unsupported = []
    for part in parts:
        name, separator, raw_value = part.partition(":")
        name = name.strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
            raise _InvalidRule(f"Invalid option name: {name}")
        value = raw_value.strip() if separator else None
        option = RuleOption(name, value)
        options.append(option)
        if name not in _KEYWORDS:
            unsupported.append(name)
            continue
        if name not in _MODIFIERS and name != "content":
            if name in singleton:
                raise _InvalidRule(f"Duplicate option: {name}")
            singleton.add(name)
        if name == "content":
            _content(value)
            content_count += 1
            modifiers = set()
        elif name in _MODIFIERS:
            if modifiers is None:
                raise _InvalidRule(f"{name} requires a preceding content")
            if name in modifiers:
                raise _InvalidRule(f"Duplicate {name} for one content")
            modifiers.add(name)
            if name == "nocase":
                if separator:
                    raise _InvalidRule("nocase takes no value")
            else:
                if name in {"distance", "within"} and content_count < 2:
                    raise _InvalidRule(f"{name} requires a previous content match")
                minimum = None if name == "distance" else (1 if name in {"depth", "within"} else 0)
                _integer(value, name, minimum, signed=name == "distance")
        elif name == "msg":
            if not _quoted(value, name):
                raise _InvalidRule("msg must not be empty")
        elif name in {"sid", "rev", "priority"}:
            _integer(value, name, 1)
        elif name == "classtype":
            if value is None or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", value) is None:
                raise _InvalidRule("classtype requires an identifier")
        elif name in {"flags", "dsize"}:
            _packet_option(option, protocol)
        elif name == "flow":
            if not value:
                raise _InvalidRule("flow requires a value")
            terms = [term.strip() for term in value.split(",")]
            if not all(terms) or len(set(terms)) != len(terms):
                raise _InvalidRule("Empty or duplicate flow term")
            unknown = set(terms) - {"to_server", "to_client", "established", "not_established"}
            unsupported.extend(f"flow:{term}" for term in sorted(unknown))
            if {"to_server", "to_client"} <= set(terms) or {"established", "not_established"} <= set(terms):
                raise _InvalidRule("Conflicting flow terms")
    missing = {"msg", "sid", "rev"} - singleton
    if missing:
        raise _InvalidRule("Missing required options: " + ", ".join(sorted(missing)))
    if unsupported:
        raise _UnsupportedRule("Unsupported options: " + ", ".join(unsupported))
    return tuple(options)


class RuleParserValidator:
    def parse(self, source: RuleText) -> RuleValidationResult:
        """Validate a rule and return its status."""

        try:
            header_text, parts = _split_rule(source.text)
            header = _header(header_text)
            options = _options(parts, header.protocol)
            values = {option.name: option.value for option in options}
            rule = InternalRule(
                header=header,
                sid=_integer(values["sid"], "sid", 1),
                rev=_integer(values["rev"], "rev", 1),
                msg=_quoted(values["msg"], "msg"),
                options=options,
                priority=_integer(values["priority"], "priority", 1) if "priority" in values else None,
                classtype=values.get("classtype"),
            )
            return RuleValidationResult(source, "valid", rule, "Basic syntax/types validated; matching and deep semantic checks are not implemented")
        except _UnsupportedRule as exc:
            return RuleValidationResult(source, "unsupported", None, str(exc))
        except (ValueError, TypeError) as exc:
            return RuleValidationResult(source, "invalid", None, str(exc))
