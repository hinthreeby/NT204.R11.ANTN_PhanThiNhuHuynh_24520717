import json
from pathlib import Path


path = Path(
    "TEST/T11_concurrent_flows/events.jsonl"
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


assert len(events) == 4


flow_1_forward = events[0]
flow_2_forward = events[1]

flow_1_backward = events[2]
flow_2_backward = events[3]


flow_1_id = (
    flow_1_forward["flow"]["flow_id"]
)

flow_2_id = (
    flow_2_forward["flow"]["flow_id"]
)


# Different 5-tuples must create different flows.
assert (
    flow_1_id
    != flow_2_id
)


# Reverse packets must return to their original flow.
assert (
    flow_1_backward["flow"]["flow_id"]
    == flow_1_id
)

assert (
    flow_2_backward["flow"]["flow_id"]
    == flow_2_id
)


assert (
    flow_1_forward["flow"]["direction"]
    == "forward"
)

assert (
    flow_2_forward["flow"]["direction"]
    == "forward"
)

assert (
    flow_1_backward["flow"]["direction"]
    == "backward"
)

assert (
    flow_2_backward["flow"]["direction"]
    == "backward"
)


unique_flow_ids = {
    event["flow"]["flow_id"]
    for event in events
}


assert len(unique_flow_ids) == 2


print("T11 PASS")