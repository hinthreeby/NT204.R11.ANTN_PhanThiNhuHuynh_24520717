import json
import contextlib
import io
import sys
import tempfile
from copy import deepcopy
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from capture.pcap_reader import read_pcap
from config import IDSConfig
from flow.flow_tracker import FlowTracker
from main import process_event_file
from pipeline import IDSPipeline
from scapy.layers.inet import IP, TCP
from scapy.utils import wrpcap


path = Path(__file__).resolve().parent / "events.jsonl"


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


# Keep the original fixture and all assertions above unchanged.
for event in events:
    for summary in event["expired_flows"]:
        assert summary["close_reason"] == "idle_timeout"
        assert summary["expired"] is True
        assert summary["duration"] == summary["last_seen"] - summary["start_time"]
        assert "direction" not in summary


def make_event(protocol, timestamp, backward=False, size=60):
    src, dst, sport, dport = "10.1.0.1", "10.1.0.2", 50000, 9999
    if backward:
        src, dst, sport, dport = dst, src, dport, sport
    return {
        "timestamp": timestamp,
        "network": {"protocol": "IPv4", "src_ip": src, "dst_ip": dst, "total_length": size},
        "transport": {"protocol": protocol, "src_port": sport, "dst_port": dport,
                      "flags": ["SYN", "ACK"] if backward else ["SYN"], "payload_length": 0},
        "application": {"protocol": "UNKNOWN"}, "errors": [],
    }


for protocol, timeout in [("UDP", 60.0), ("TCP", 300.0)]:
    tracker = FlowTracker(IDSConfig())
    first = tracker.process(make_event(protocol, 1000.0))
    second = tracker.process(make_event(protocol, 1005.0, backward=True, size=80))
    third_input = make_event(protocol, 1008.0, size=40)
    third_input["transport"]["flags"] = ["ACK"]
    third = tracker.process(third_input)
    flow_id = first["flow"]["flow_id"]
    assert second["flow"]["flow_id"] == third["flow"]["flow_id"] == flow_id
    old_object = next(iter(tracker.active_flows.values()))
    old_snapshot = deepcopy(old_object)
    assert tracker.expire_idle_flows(900.0) == []
    assert tracker.expire_idle_flows(1008.0 + timeout - 0.1) == []
    assert tracker.expire_idle_flows(1008.0 + timeout) == []
    assert len(tracker.active_flows) == 1
    assert old_object == old_snapshot

    summaries = tracker.expire_idle_flows(1008.0 + timeout + 0.1)
    assert len(summaries) == 1
    summary = summaries[0]
    assert summary["flow_id"] == flow_id
    assert summary["close_reason"] == "idle_timeout"
    assert summary["expired"] is True
    assert summary["packet_count"] == 3
    assert summary["byte_count"] == 180
    assert summary["forward_packet_count"] == 2
    assert summary["forward_byte_count"] == 100
    assert summary["backward_packet_count"] == 1
    assert summary["backward_byte_count"] == 80
    assert (summary["start_time"], summary["last_seen"], summary["duration"]) == (1000.0, 1008.0, 8.0)
    assert old_object == old_snapshot
    expected = dict(third["flow"])
    expected.pop("direction")
    assert {key: summary[key] for key in expected} == expected
    if protocol == "TCP":
        assert summary["state"] == "ESTABLISHED"
        assert (summary["SYN_count"], summary["ACK_count"], summary["FIN_count"], summary["RST_count"]) == (2, 2, 0, 0)
    assert tracker.active_flows == {}
    assert tracker.expire_idle_flows(1008.0 + timeout + 0.1) == []
    assert tracker.expire_idle_flows(1008.0 + timeout + 0.2) == []

    reopened = tracker.process(make_event(protocol, 1009.0 + timeout))
    assert reopened["flow"]["flow_id"] != flow_id
    assert reopened["flow"]["packet_count"] == 1
    assert reopened["flow"]["byte_count"] == 60
    assert reopened["flow"]["forward_byte_count"] == 60
    assert reopened["flow"]["backward_byte_count"] == 0
    assert reopened["flow"]["duration"] == 0
    assert reopened["expired_flows"] == []
    print(f"T12 {protocol}: strict timeout boundary, complete summary, cleanup and independent reuse PASS")

tracker = FlowTracker(IDSConfig(tcp_idle_timeout=7.0, udp_idle_timeout=2.0))
udp = tracker.process(make_event("UDP", 1000.0))
tcp = tracker.process(make_event("TCP", 1000.0))
assert tracker.expire_idle_flows(1002.0) == []
summaries = tracker.expire_idle_flows(1002.5)
assert [item["flow_id"] for item in summaries] == [udp["flow"]["flow_id"]]
assert len(tracker.active_flows) == 1
assert tracker.expire_idle_flows(1007.0) == []
summaries = tracker.expire_idle_flows("1007.5")
assert [item["flow_id"] for item in summaries] == [tcp["flow"]["flow_id"]]
assert tracker.active_flows == {}
zero = FlowTracker(IDSConfig(udp_idle_timeout=0.0))
zero.process(make_event("UDP", 0.0))
assert zero.expire_idle_flows(0.0) == []
assert len(zero.expire_idle_flows(0.001)) == 1
print("T12 separate custom TCP/UDP timeouts and zero-timeout boundary PASS")

# A usable event timestamp advances cleanup even without a trackable flow key.
for marker in [
    {"timestamp": 1003.0},
    {"timestamp": 1003.0, "preprocess_status": "invalid"},
    {"timestamp": 1003.0, "processing_action": "skip"},
    {"timestamp": 1003.0, "network": {}, "transport": {"protocol": "ICMP"}},
]:
    tracker = FlowTracker(IDSConfig(udp_idle_timeout=2.0))
    tracker.process(make_event("UDP", 1000.0))
    result = tracker.process(marker)
    assert result["flow"]["tracked"] is False
    assert len(result["expired_flows"]) == 1
    assert result["expired_flows"][0]["close_reason"] == "idle_timeout"
    assert tracker.active_flows == {}
    assert tracker.expire_idle_flows(1003.0) == []

tracker = FlowTracker(IDSConfig())
tracker.process(make_event("UDP", 1000.0))
snapshot = deepcopy(tracker.active_flows)
for invalid_time in (None, "invalid", -1, True, float("nan"), float("inf"), -float("inf"), {}, [], 10 ** 1000):
    assert tracker.expire_idle_flows(invalid_time) == []
    assert tracker.active_flows == snapshot
    malformed = make_event("UDP", invalid_time)
    result = tracker.process(malformed)
    assert result["flow"]["tracked"] is False
    assert result["expired_flows"] == []
    assert tracker.active_flows == snapshot
for malformed in (None, [], "invalid", {}, {"timestamp": 1001.0, "network": []}):
    assert tracker.process(malformed)["flow"]["tracked"] is False
    assert tracker.active_flows == snapshot
for bad_key in (["not-an-ip"], {"not": "an ip"}):
    malformed = make_event("UDP", 1001.0)
    malformed["network"]["src_ip"] = bad_key
    assert tracker.process(malformed)["flow"]["tracked"] is False
assert tracker.active_flows == snapshot
late = tracker.process(make_event("UDP", 999.0))
assert late["flow"]["last_seen"] == 1000.0
assert late["flow"]["start_time"] == 1000.0
assert late["flow"]["duration"] == 0
assert late["flow"]["packet_count"] == 2
print("T12 malformed/skip markers, invalid clocks and out-of-order timestamps PASS")

# The pipeline exposes explicit cleanup without silently discarding summaries.
pipeline = IDSPipeline(IDSConfig(udp_idle_timeout=2.0, skip_invalid_events=True))
pipeline.process_event(make_event("UDP", 1000.0))
assert pipeline.process_event({"timestamp": 1003.0}) is None
assert len(pipeline.flow_tracker.active_flows) == 1
summaries = pipeline.expire_idle_flows(1003.0)
assert len(summaries) == 1
assert summaries[0]["packet_count"] == 1
assert summaries[0]["close_reason"] == "idle_timeout"
assert pipeline.expire_idle_flows(1003.0) == []
assert pipeline.flow_tracker.active_flows == {}
pipeline = IDSPipeline(IDSConfig(udp_idle_timeout=2.0))
pipeline.process_event(make_event("UDP", 1000.0))
invalid = pipeline.process_event({"timestamp": 1003.0})
assert invalid is not None
assert invalid["flow"]["tracked"] is False
assert len(invalid["expired_flows"]) == 1

# Terminal TCP cleanup keeps its actual ending reason, not idle_timeout.
for terminal, flags, reason in [("RESET", ["RST"], "tcp_reset"), ("CLOSED", ["FIN", "ACK"], "tcp_closed")]:
    pipeline = IDSPipeline(IDSConfig(tcp_idle_timeout=2.0))
    pipeline.process_event(make_event("TCP", 1000.0))
    ending = make_event("TCP", 1001.0)
    ending["transport"]["flags"] = flags
    pipeline.process_event(ending)
    if terminal == "CLOSED":
        ending = make_event("TCP", 1002.0, backward=True)
        ending["transport"]["flags"] = flags
        pipeline.process_event(ending)
    summaries = pipeline.expire_idle_flows(1005.0)
    assert len(summaries) == 1
    assert summaries[0]["state"] == terminal
    assert summaries[0]["close_reason"] == reason
    assert pipeline.flow_tracker.active_flows == {}
print("T12 explicit pipeline cleanup, skipped events and TCP termination reasons PASS")

# Reading EOF alone must not synthesize a future capture timestamp.
with tempfile.TemporaryDirectory(prefix="t12-eof-") as temp:
    temp_path = Path(temp)
    source = temp_path / "input.jsonl"
    destination = temp_path / "events.jsonl"
    source.write_text(json.dumps(make_event("UDP", 1000.0)) + "\n", encoding="utf-8")
    pipeline = IDSPipeline()
    with contextlib.redirect_stdout(io.StringIO()):
        process_event_file(str(source), str(destination), pipeline)
    output = json.loads(destination.read_text(encoding="utf-8"))
    assert output["expired_flows"] == []
    assert len(pipeline.flow_tracker.active_flows) == 1
    assert pipeline.expire_idle_flows(1060.0) == []
    assert len(pipeline.expire_idle_flows(1060.1)) == 1

    packet = IP(src="10.1.0.1", dst="10.1.0.2") / TCP(sport=50000, dport=80, flags="S")
    packet.time = 1000.0
    capture = temp_path / "input.pcap"
    wrpcap(str(capture), [packet])
    pipeline = IDSPipeline()
    with contextlib.redirect_stdout(io.StringIO()):
        read_pcap(str(capture), str(destination), pipeline.process_packet)
    output = json.loads(destination.read_text(encoding="utf-8"))
    assert output is not None
    assert output["expired_flows"] == []
    assert len(pipeline.flow_tracker.active_flows) == 1
    assert pipeline.expire_idle_flows(1300.0) == []
    assert len(pipeline.expire_idle_flows(1300.1)) == 1
print("T12 JSONL/PCAP EOF does not imply timeout PASS")
print("T12 PASS")
