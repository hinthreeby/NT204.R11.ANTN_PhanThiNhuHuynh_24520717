import json
from pathlib import Path


path = Path(
    "TEST/T13_flow_statistics/events.jsonl"
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


assert len(events) == 6


# All packets belong to one flow.
flow_ids = {
    event["flow"]["flow_id"]
    for event in events
}

assert len(flow_ids) == 1


flow = events[-1]["flow"]


assert flow["packet_count"] == 6
assert flow["byte_count"] == 444


assert (
    flow["forward_packet_count"]
    == 4
)

assert (
    flow["forward_byte_count"]
    == 264
)


assert (
    flow["backward_packet_count"]
    == 2
)

assert (
    flow["backward_byte_count"]
    == 180
)


assert flow["SYN_count"] == 2
assert flow["ACK_count"] == 5
assert flow["FIN_count"] == 1
assert flow["RST_count"] == 0


assert (
    abs(
        flow["duration"] - 5.0
    )
    < 0.000001
)


assert (
    flow["state"]
    == "CLOSING"
)


print("T13 PASS")