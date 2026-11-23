from ipaddress import IPv4Address
import math


class DetectionValidationError(ValueError):
    """Identify missing or invalid Detection Event data."""


def _integer(value, field: str, minimum: int, maximum: int | None = None) -> int:
    if type(value) is not int or value < minimum or (maximum is not None and value > maximum):
        raise DetectionValidationError(f"Invalid {field}: expected an integer in the allowed range")
    return value


def _text(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DetectionValidationError(f"Invalid {field}: expected a non-empty string")
    return value.strip()


def _evidence(value) -> tuple[dict, ...]:
    if not isinstance(value, list) or not value:
        raise DetectionValidationError("Invalid match_information: expected a non-empty list")
    result = []
    for index, item in enumerate(value):
        location = f"match_information[{index}]"
        if not isinstance(item, dict):
            raise DetectionValidationError(f"Invalid {location}: expected a dictionary")
        field = _text(item.get("field"), f"{location}.field")
        start, end = item.get("start"), item.get("end")
        if start is not None or end is not None:
            _integer(start, f"{location}.start", 0)
            _integer(end, f"{location}.end", start)
        option_index = item.get("option_index")
        if option_index is not None:
            _integer(option_index, f"{location}.option_index", 0)
        raw = item.get("matched_hex")
        if raw is not None:
            if not isinstance(raw, str):
                raise DetectionValidationError(f"Invalid {location}.matched_hex")
            try:
                data = bytes.fromhex(raw)
            except ValueError as exc:
                raise DetectionValidationError(f"Invalid {location}.matched_hex") from exc
            if start is not None and len(data) != end - start:
                raise DetectionValidationError(f"Invalid {location}: byte length conflicts with span")
            raw = data.hex()
        result.append(dict(field=field, start=start, end=end, matched_hex=raw, option_index=option_index))
    return tuple(result)


def validate_detection_event(event: object) -> dict:
    """Return normalized fields or raise a specific source-data error."""

    if not isinstance(event, dict):
        raise DetectionValidationError("Detection Event must be a dictionary")
    required = (
        "timestamp", "sid", "rev", "msg", "src_ip", "src_port", "dst_ip", "dst_port",
        "protocol", "application_protocol", "flow_id", "match_information",
    )
    for field in required:
        if field not in event:
            raise DetectionValidationError(f"Missing required field: {field}")
    timestamp = event["timestamp"]
    if type(timestamp) not in (int, float):
        raise DetectionValidationError("Invalid timestamp: expected finite non-negative seconds")
    try:
        timestamp = float(timestamp)
    except OverflowError as exc:
        raise DetectionValidationError("Invalid timestamp: outside the supported numeric range") from exc
    if not math.isfinite(timestamp) or timestamp < 0:
        raise DetectionValidationError("Invalid timestamp: expected finite non-negative seconds")
    normalized = {
        "timestamp": timestamp,
        "sid": _integer(event["sid"], "sid", 1),
        "rev": _integer(event["rev"], "rev", 1),
        "message": _text(event["msg"], "msg"),
    }
    for field in ("src_ip", "dst_ip"):
        text = _text(event[field], field)
        try:
            normalized[field] = str(IPv4Address(text))
        except ValueError as exc:
            raise DetectionValidationError(f"Invalid {field}: expected IPv4") from exc
    for field in ("src_port", "dst_port"):
        normalized[field] = _integer(event[field], field, 0, 65535)
    for field, allowed in (
        ("protocol", {"TCP", "UDP"}),
        ("application_protocol", {"HTTP", "DNS", "SMTP", "UNKNOWN"}),
    ):
        text = _text(event[field], field).upper()
        if text not in allowed:
            raise DetectionValidationError(f"Invalid {field}: unsupported protocol")
        normalized[field] = text
    flow_id = event["flow_id"]
    normalized["flow_id"] = None if flow_id is None else _text(flow_id, "flow_id")
    priority = event.get("priority")
    normalized["priority"] = None if priority is None else _integer(priority, "priority", 1)
    classtype = event.get("classtype")
    normalized["classtype"] = None if classtype is None else _text(classtype, "classtype")
    normalized["match_information"] = _evidence(event["match_information"])
    return normalized
