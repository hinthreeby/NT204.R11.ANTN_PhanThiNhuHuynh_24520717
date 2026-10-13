import json
from pathlib import Path


path = Path(
    "TEST/T06_missing_field/events.jsonl"
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
    event["application"]["protocol"]
    == "UNKNOWN"
)

assert (
    event["errors"]
    == []
)

assert (
    event["preprocess_status"]
    == "partial"
)

assert (
    event["processing_action"]
    == "continue"
)

assert event["reason"]


print("T06 PASS")