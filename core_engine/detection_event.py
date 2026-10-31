"""Build detection events from confirmed rule matches."""

from collections.abc import Sequence
from dataclasses import asdict
from ipaddress import IPv4Address
import json
import math

from .contracts import FlowContext, NormalizedEvent
from .models import DetectionEvent, EvaluationResult, InternalRule, MatchInformation, MatchResult


class DetectionEventDataError(ValueError):
    """Report missing or inconsistent detection source data."""


def _integer(value, field: str, minimum: int, maximum: int | None = None) -> None:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise DetectionEventDataError(f"Invalid {field}")


def _validate_detection(event: DetectionEvent) -> None:
    """Check detection values before exposing JSON-compatible output."""

    if type(event.timestamp) not in (int, float):
        raise DetectionEventDataError("Missing or invalid timestamp")
    try:
        valid_time = math.isfinite(event.timestamp) and event.timestamp >= 0
    except OverflowError:
        valid_time = False
    if not valid_time:
        raise DetectionEventDataError("Missing or invalid timestamp")
    for field in ("sid", "rev"):
        _integer(getattr(event, field), field, 1)
    if not isinstance(event.msg, str) or not event.msg:
        raise DetectionEventDataError("Missing or invalid msg")
    for field in ("src_ip", "dst_ip"):
        value = getattr(event, field)
        if not isinstance(value, str):
            raise DetectionEventDataError(f"Missing or invalid {field}")
        try:
            IPv4Address(value)
        except ValueError as exc:
            raise DetectionEventDataError(f"Invalid {field}") from exc
    for field in ("src_port", "dst_port"):
        _integer(getattr(event, field), field, 0, 65535)
    if event.protocol not in ("TCP", "UDP"):
        raise DetectionEventDataError("Invalid protocol")
    if event.application_protocol not in ("HTTP", "DNS", "SMTP", "UNKNOWN"):
        raise DetectionEventDataError("Invalid application_protocol")
    if event.flow_id is not None and (not isinstance(event.flow_id, str) or not event.flow_id.strip()):
        raise DetectionEventDataError("Invalid flow_id")
    if event.priority is not None:
        _integer(event.priority, "priority", 1)
    if event.classtype is not None and (not isinstance(event.classtype, str) or not event.classtype):
        raise DetectionEventDataError("Invalid classtype")
    if not isinstance(event.match_information, tuple) or not event.match_information:
        raise DetectionEventDataError("Missing or invalid match_information")
    for info in event.match_information:
        if not isinstance(info, MatchInformation):
            raise TypeError("Expected MatchInformation objects")
        if not isinstance(info.field, str) or not info.field:
            raise DetectionEventDataError("Invalid match_information.field")
        if info.start is not None or info.end is not None:
            _integer(info.start, "match_information.start", 0)
            _integer(info.end, "match_information.end", info.start)
        if info.option_index is not None:
            _integer(info.option_index, "match_information.option_index", 0)
        if info.matched_hex is not None:
            if not isinstance(info.matched_hex, str):
                raise DetectionEventDataError("Invalid match_information.matched_hex")
            try:
                raw = bytes.fromhex(info.matched_hex)
            except ValueError as exc:
                raise DetectionEventDataError("Invalid match_information.matched_hex") from exc
            if info.start is not None and len(raw) != info.end - info.start:
                raise DetectionEventDataError("Match byte length conflicts with span")


def _flow_id(event: NormalizedEvent, context: FlowContext | None) -> str | None:
    """Resolve flow identity without inventing or replacing evidence."""

    embedded = event.get("flow")
    if embedded is not None and not isinstance(embedded, dict):
        raise DetectionEventDataError("Invalid event.flow")
    if context is None:
        context = embedded
    if context is None:
        return None
    if not isinstance(context, dict):
        raise DetectionEventDataError("Invalid flow_context")
    value = context.get("flow_id")
    if embedded is not None and "flow_id" in embedded and embedded["flow_id"] != value:
        raise DetectionEventDataError("Conflicting flow_id sources")
    if context.get("tracked") is True and (not isinstance(value, str) or not value.strip()):
        raise DetectionEventDataError("Tracked flow is missing a valid flow_id")
    if context.get("tracked") is False and value is not None:
        raise DetectionEventDataError("Untracked flow must not carry a flow_id")
    return value


class DetectionEventGenerator:
    def generate(
        self,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
        match_result: MatchResult,
    ) -> DetectionEvent:
        """Convert one confirmed match using its source event and context."""

        if not isinstance(match_result, MatchResult) or not isinstance(match_result.rule, InternalRule):
            raise TypeError("Expected a MatchResult containing an InternalRule")
        if match_result.status != "MATCH":
            raise ValueError("Detection generation requires MATCH status")
        if not isinstance(normalized_event, dict):
            raise TypeError("Expected a normalized event dictionary")
        if normalized_event.get("processing_action") == "skip" or normalized_event.get("preprocess_status") == "invalid":
            raise DetectionEventDataError("Cannot generate detection for an invalid or skipped event")
        network, transport = normalized_event.get("network"), normalized_event.get("transport")
        if not isinstance(network, dict) or not isinstance(transport, dict):
            raise DetectionEventDataError("Missing or invalid network/transport fields")
        application = normalized_event.get("application")
        application_protocol = application.get("protocol") if isinstance(application, dict) else None
        if application_protocol not in ("HTTP", "DNS", "SMTP", "UNKNOWN"):
            application_protocol = "UNKNOWN"
        rule = match_result.rule
        detection = DetectionEvent(
            timestamp=normalized_event.get("timestamp"),
            sid=rule.sid, rev=rule.rev, msg=rule.msg,
            src_ip=network.get("src_ip"), src_port=transport.get("src_port"),
            dst_ip=network.get("dst_ip"), dst_port=transport.get("dst_port"),
            protocol=transport.get("protocol"), application_protocol=application_protocol,
            flow_id=_flow_id(normalized_event, flow_context),
            match_information=match_result.information,
            priority=rule.priority, classtype=rule.classtype,
        )
        _validate_detection(detection)
        return detection

    def generate_all(
        self,
        normalized_event: NormalizedEvent,
        flow_context: FlowContext | None,
        evaluation_result: EvaluationResult | Sequence[MatchResult] | None,
    ) -> tuple[DetectionEvent, ...]:
        """Convert all matches without merging rules or returning partial batches."""

        if evaluation_result is None:
            return ()
        matches = evaluation_result.matches if isinstance(evaluation_result, EvaluationResult) else evaluation_result
        if not isinstance(matches, Sequence) or isinstance(matches, (str, bytes)):
            raise TypeError("Expected EvaluationResult or a sequence of MatchResult objects")
        detections = []
        for match in matches:
            if not isinstance(match, MatchResult):
                raise TypeError("Expected MatchResult objects")
            if match.status == "NO_MATCH":
                continue
            detections.append(self.generate(normalized_event, flow_context, match))
        return tuple(detections)

    @staticmethod
    def to_dict(detection: DetectionEvent) -> dict:
        """Return detached JSON-compatible detection data with explicit nulls."""

        if not isinstance(detection, DetectionEvent):
            raise TypeError("Expected a DetectionEvent")
        _validate_detection(detection)
        return json.loads(json.dumps(asdict(detection), ensure_ascii=False, allow_nan=False))
