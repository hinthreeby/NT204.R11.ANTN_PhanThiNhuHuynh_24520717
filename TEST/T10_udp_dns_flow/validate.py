import json
from pathlib import Path


path = Path(
    "TEST/T10_udp_dns_flow/events.jsonl"
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


query = events[0]
response = events[1]


assert (
    query["flow"]["flow_id"]
    == response["flow"]["flow_id"]
)

assert (
    query["flow"]["direction"]
    == "forward"
)

assert (
    response["flow"]["direction"]
    == "backward"
)


flow = response["flow"]


assert flow["protocol"] == "UDP"

assert flow["packet_count"] == 2
assert flow["byte_count"] == 150

assert (
    flow["forward_packet_count"]
    == 1
)

assert (
    flow["forward_byte_count"]
    == 60
)

assert (
    flow["backward_packet_count"]
    == 1
)

assert (
    flow["backward_byte_count"]
    == 90
)

assert (
    abs(
        flow["duration"] - 0.5
    )
    < 0.000001
)

assert flow["state"] is None


print("T10 PASS")