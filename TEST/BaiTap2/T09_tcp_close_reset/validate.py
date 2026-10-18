import json
import sys
from copy import deepcopy
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from config import IDSConfig
from flow.flow_tracker import FlowTracker


path = Path(__file__).resolve().parent / "events.jsonl"


with path.open(
    "r",
    encoding="utf-8",
) as file:
    all_events = [
        json.loads(line)
        for line in file
        if line.strip()
    ]


# Preserve the original nine-packet evidence and its assertions.
assert len(all_events) == 17
events = all_events[:9]


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


reopened_reset = all_events[9:12]
reopened_closed = all_events[12:17]
connections = [normal_flow, reset_flow, reopened_reset, reopened_closed]
assert len({connection[0]["flow"]["flow_id"] for connection in connections}) == 4

for connection in connections:
    assert len({event["flow"]["flow_id"] for event in connection}) == 1
    assert [event["flow"]["state"] for event in connection[:3]] == [
        "HANDSHAKE", "HANDSHAKE", "ESTABLISHED",
    ]
    assert [event["flow"]["direction"] for event in connection[:3]] == [
        "forward", "backward", "forward",
    ]
    for index, event in enumerate(connection):
        flow = event["flow"]
        assert flow["packet_count"] == index + 1
        assert flow["start_time"] == connection[0]["timestamp"]
        assert flow["last_seen"] == event["timestamp"]
        assert abs(flow["duration"] - (event["timestamp"] - connection[0]["timestamp"])) < 0.000001

assert reopened_closed[0]["flow"]["endpoint_a"] == {"ip": "192.168.1.20", "port": 80}
assert [event["flow"]["state"] for event in reopened_closed[3:]] == ["CLOSING", "CLOSED"]

# Final counters include the FIN/RST packets of the original connection.
for connection, packets, forward, backward, byte_count, forward_bytes, backward_bytes, fin, rst in [
    (normal_flow, 5, 3, 2, 0, 0, 0, 2, 0),
    (reset_flow, 4, 2, 2, 0, 0, 0, 0, 1),
    (reopened_reset, 3, 2, 1, 120, 80, 40, 0, 0),
    (reopened_closed, 5, 3, 2, 200, 120, 80, 2, 0),
]:
    flow = connection[-1]["flow"]
    assert flow["packet_count"] == packets
    assert flow["forward_packet_count"] == forward
    assert flow["backward_packet_count"] == backward
    assert flow["byte_count"] == byte_count
    assert flow["forward_byte_count"] == forward_bytes
    assert flow["backward_byte_count"] == backward_bytes
    assert flow["SYN_count"] == 2
    assert flow["ACK_count"] == packets - 1
    assert flow["FIN_count"] == fin
    assert flow["RST_count"] == rst

for event, old_connection, reason in [
    (reopened_reset[0], reset_flow, "tcp_reset"),
    (reopened_closed[0], normal_flow, "tcp_closed"),
]:
    assert len(event["expired_flows"]) == 1
    summary = event["expired_flows"][0]
    assert summary["close_reason"] == reason
    assert summary["expired"] is True
    expected = dict(old_connection[-1]["flow"])
    expected.pop("direction")
    assert {key: summary[key] for key in expected} == expected


# Minimal SYN -> RST -> SYN, equal timestamps, and delayed non-opening packets.
inputs = [json.loads(line) for line in path.with_name("input.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
for terminal, terminal_index in [("RESET", 8), ("CLOSED", 4)]:
    tracker = FlowTracker(IDSConfig())
    sequence = inputs[5:9] if terminal == "RESET" else inputs[:5]
    old_object = None
    for event in sequence:
        result = tracker.process(event)
        old_object = next(iter(tracker.active_flows.values()))
    assert result["flow"]["state"] == terminal

    # ACK or SYN/ACK is not a new opening SYN.
    for flags in (["ACK"], ["SYN", "ACK"], ["SYN", "RST"], ["SYN", "FIN"]):
        delayed = deepcopy(inputs[terminal_index])
        delayed["transport"]["flags"] = flags
        result = tracker.process(delayed)
        assert result["flow"]["flow_id"] == old_object.flow_id
        assert result["flow"]["state"] == terminal
        assert result["expired_flows"] == []
    old_snapshot = deepcopy(old_object)

    syn = deepcopy(sequence[0])
    # Same timestamp as the old SYN must still produce a distinct ID.
    reopened = tracker.process(syn)
    new_object = next(iter(tracker.active_flows.values()))
    assert new_object is not old_object
    assert old_object == old_snapshot
    assert new_object.flow_id != old_object.flow_id
    assert reopened["flow"]["state"] == "HANDSHAKE"
    assert reopened["flow"]["packet_count"] == 1
    assert reopened["flow"]["duration"] == 0
    assert reopened["expired_flows"][0]["close_reason"] == ("tcp_reset" if terminal == "RESET" else "tcp_closed")

    # SYN retransmission stays in this connection; RST then SYN starts another.
    assert tracker.process(syn)["flow"]["flow_id"] == new_object.flow_id
    rst_event = deepcopy(syn)
    rst_event["transport"]["flags"] = ["RST"]
    reset = tracker.process(rst_event)
    assert reset["flow"]["state"] == "RESET"
    assert reset["flow"]["packet_count"] == 3
    next_syn = tracker.process(syn)
    assert next_syn["flow"]["flow_id"] not in {old_object.flow_id, new_object.flow_id}
    assert next_syn["flow"]["state"] == "HANDSHAKE"
    active_expiration = tracker.expire_idle_flows(syn["timestamp"] + 301)
    assert len(active_expiration) == 1
    assert active_expiration[0]["close_reason"] == "idle_timeout"

    # A terminal flow removed by timeout keeps its TCP termination reason.
    tracker = FlowTracker(IDSConfig())
    for event in sequence:
        tracker.process(event)
    summaries = tracker.expire_idle_flows(sequence[-1]["timestamp"] + 301)
    assert len(summaries) == 1
    assert summaries[0]["close_reason"] == ("tcp_reset" if terminal == "RESET" else "tcp_closed")
    assert tracker.active_flows == {}

print("T09 original close/reset and same-tuple reuse PASS")
print("T09 counters, direction, duration, object isolation and termination reasons PASS")
print("T09 PASS")
