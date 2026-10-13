import json
from pathlib import Path


path = Path(
    "TEST/T07_tcp_handshake_tracking/events.jsonl"
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


assert len(events) == 3


syn_event = events[0]
syn_ack_event = events[1]
ack_event = events[2]


# All packets must belong to one flow.
flow_ids = {
    event["flow"]["flow_id"]
    for event in events
}

assert len(flow_ids) == 1


# Direction
assert (
    syn_event["flow"]["direction"]
    == "forward"
)

assert (
    syn_ack_event["flow"]["direction"]
    == "backward"
)

assert (
    ack_event["flow"]["direction"]
    == "forward"
)


# TCP state transitions
assert (
    syn_event["flow"]["state"]
    == "HANDSHAKE"
)

assert (
    syn_ack_event["flow"]["state"]
    == "HANDSHAKE"
)

assert (
    ack_event["flow"]["state"]
    == "ESTABLISHED"
)


# Handshake packets have no payload.
for event in events:
    assert (
        event["transport"]["payload_length"]
        == 0
    )


print("T07 PASS")