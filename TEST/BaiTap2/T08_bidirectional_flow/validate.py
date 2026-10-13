import json
from pathlib import Path


path = Path(
    "TEST/T08_bidirectional_flow/events.jsonl"
)


with path.open(
    "r",
    encoding="utf-8",
) as file:
    events = [
        json.loads(line)
        for line in file
        if line.strip()
    ]


assert len(events) == 2


forward_event = events[0]
backward_event = events[1]


assert (
    forward_event["flow"]["tracked"]
    is True
)

assert (
    backward_event["flow"]["tracked"]
    is True
)


assert (
    forward_event["flow"]["flow_id"]
    ==
    backward_event["flow"]["flow_id"]
)


assert (
    forward_event["flow"]["direction"]
    == "forward"
)

assert (
    backward_event["flow"]["direction"]
    == "backward"
)


assert (
    forward_event["flow"]["endpoint_a"]
    == {
        "ip": "192.168.1.10",
        "port": 50000,
    }
)

assert (
    forward_event["flow"]["endpoint_b"]
    == {
        "ip": "192.168.1.20",
        "port": 80,
    }
)


print("T08 PASS")