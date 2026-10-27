"""Compile validated Snort content options into byte patterns."""

from dataclasses import dataclass

from .models import InternalRule, RuleOption
from .rule_parser import _content


_MODIFIERS = {"nocase", "offset", "depth", "distance", "within"}


@dataclass(frozen=True, slots=True)
class ContentPattern:
    pattern: bytes
    nocase: bool
    content_index: int
    option_index: int
    modifiers: tuple[RuleOption, ...]


def compile_content_bytes(value: str) -> bytes:
    """Decode supported escapes and hex blocks, encoding literals as UTF-8."""

    if not isinstance(value, str):
        raise ValueError("content requires a double-quoted value")
    if any(char in value for char in "\x00\r\n"):
        raise ValueError("Expected content without literal NUL/CR/LF")
    _content(value)
    pattern = bytearray()
    index = 1
    while index < len(value) - 1:
        char = value[index]
        if char == "\\":
            index += 1
            char = value[index]
        elif char == "|":
            end = value.index("|", index + 1)
            pattern.extend(bytes.fromhex("".join(value[index + 1:end].split())))
            index = end + 1
            continue
        try:
            pattern.extend(char.encode("utf-8"))
        except UnicodeEncodeError as exc:
            raise ValueError("Content literal cannot be encoded as UTF-8") from exc
        index += 1
    return bytes(pattern)


def compile_content_patterns(rule: InternalRule) -> tuple[ContentPattern, ...]:
    """Compile ordered content options and retain their own modifiers."""

    if not isinstance(rule, InternalRule):
        raise TypeError("Expected a validated InternalRule")
    patterns = []
    pattern = None
    option_index = 0
    modifiers = []

    def finish() -> None:
        if pattern is not None:
            patterns.append(ContentPattern(
                pattern=pattern,
                nocase=any(option.name == "nocase" for option in modifiers),
                content_index=len(patterns),
                option_index=option_index,
                modifiers=tuple(modifiers),
            ))

    for index, option in enumerate(rule.options):
        if option.name == "content":
            finish()
            try:
                pattern = compile_content_bytes(option.value)
            except ValueError as exc:
                raise ValueError(f"Content option at index {index}: {exc}") from exc
            option_index = index
            modifiers = []
        elif option.name in _MODIFIERS:
            if pattern is None:
                raise ValueError(f"{option.name} requires a preceding content")
            if any(previous.name == option.name for previous in modifiers):
                raise ValueError(f"Duplicate {option.name} for one content")
            if option.name == "nocase" and option.value is not None:
                raise ValueError("nocase takes no value")
            modifiers.append(option)
    finish()
    return tuple(patterns)
