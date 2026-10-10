import json
from pathlib import Path


path = Path(
    "TEST/T12_idle_timeout/events.jsonl"
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


# -------------------------
# UDP timeout
# -------------------------

udp_old_flow_id = (
    events[0]["flow"]["flow_id"]
)

udp_expired_ids = {
    flow["flow_id"]
    for flow in events[2][
        "expired_flows"
    ]
}

assert (
    udp_old_flow_id
    in udp_expired_ids
)


udp_new_flow_id = (
    events[3]["flow"]["flow_id"]
)

assert (
    udp_new_flow_id
    != udp_old_flow_id
)


# -------------------------
# TCP timeout
# -------------------------

tcp_old_flow_id = (
    events[1]["flow"]["flow_id"]
)

tcp_expired_ids = {
    flow["flow_id"]
    for flow in events[4][
        "expired_flows"
    ]
}

assert (
    tcp_old_flow_id
    in tcp_expired_ids
)


tcp_new_flow_id = (
    events[5]["flow"]["flow_id"]
)

assert (
    tcp_new_flow_id
    != tcp_old_flow_id
)


print("T12 PASS")