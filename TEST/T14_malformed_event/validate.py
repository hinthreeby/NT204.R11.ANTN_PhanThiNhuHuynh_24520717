import json
from pathlib import Path


path = Path(
    "TEST/T14_malformed_event/events.jsonl"
)


with path.open(
    "r",
    encoding="utf-8",
) as file:
    event = json.loads(
        next(
            line
            for line in file
            if line.strip()
        )
    )


assert (
    event["preprocess_status"]
    == "invalid"
)

assert (
    event["processing_action"]
    == "continue"
)

assert event["reason"]

assert (
    event["timestamp"]
    is None
)

assert (
    event["network"]["src_ip"]
    is None
)

assert (
    event["transport"]["src_port"]
    is None
)

assert (
    event["transport"]["dst_port"]
    is None
)

assert (
    event["application"]["protocol"]
    == "UNKNOWN"
)

assert (
    event["errors"]
    == []
)


print("T14 PASS")