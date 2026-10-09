import json
from pathlib import Path


path = Path(
    "TEST/T09_tcp_close_reset/events.jsonl"
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


assert len(events) == 9


# -------------------------
# Normal close flow
# -------------------------

normal_flow = events[:5]

normal_flow_ids = {
    event["flow"]["flow_id"]
    for event in normal_flow
}

assert len(normal_flow_ids) == 1


assert (
    events[2]["flow"]["state"]
    == "ESTABLISHED"
)

assert (
    events[3]["flow"]["state"]
    == "CLOSING"
)

assert (
    events[4]["flow"]["state"]
    == "CLOSED"
)


# -------------------------
# Reset flow
# -------------------------

reset_flow = events[5:]

reset_flow_ids = {
    event["flow"]["flow_id"]
    for event in reset_flow
}

assert len(reset_flow_ids) == 1


assert (
    events[7]["flow"]["state"]
    == "ESTABLISHED"
)

assert (
    events[8]["flow"]["state"]
    == "RESET"
)


# Two independent TCP connections.
normal_flow_id = (
    events[0]["flow"]["flow_id"]
)

reset_flow_id = (
    events[5]["flow"]["flow_id"]
)

assert (
    normal_flow_id
    != reset_flow_id
)


print("T09 PASS")