import json
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw

from config import IDSConfig
from flow.flow_tracker import FlowTracker
from pipeline import IDSPipeline


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


# Exercise the actual BaiTap1 parser schema with serialized IPv4 packets.
# Keep the original six-event fixture and all its assertions above unchanged.
pipeline = IDSPipeline()
parsed_events = []
scenarios = [
    ("forward", "S", 0, 40),
    ("backward", "SA", 0, 40),
    ("forward", "A", 0, 40),
    ("forward", "PA", 48, 88),
    ("backward", "PA", 68, 108),
    ("forward", "FA", 0, 40),
]

for index, (direction, flags, payload_length, total_length) in enumerate(scenarios):
    src, dst = "192.168.10.10", "192.168.10.20"
    sport, dport = 50000, 443
    if direction == "backward":
        src, dst = dst, src
        sport, dport = dport, sport
    packet = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    if payload_length:
        packet = packet / Raw(load=b"x" * payload_length)
    # Materialize IP.len and header fields as for packets read from a PCAP.
    packet = IP(bytes(packet))
    packet.time = 3000.0 + index
    event = pipeline.process_packet(packet, index + 1)
    assert event is not None
    assert event["errors"] == []
    assert event["network"]["total_length"] == total_length
    assert "len" not in event["network"]
    assert event["transport"]["payload_length"] == payload_length
    assert event["flow"]["direction"] == direction
    parsed_events.append(event)

assert len({event["flow"]["flow_id"] for event in parsed_events}) == 1
assert [event["flow"]["byte_count"] for event in parsed_events] == [40, 80, 120, 208, 316, 356]
assert [event["flow"]["forward_byte_count"] for event in parsed_events] == [40, 40, 80, 168, 168, 208]
assert [event["flow"]["backward_byte_count"] for event in parsed_events] == [0, 40, 40, 40, 148, 148]
assert [event["flow"]["state"] for event in parsed_events] == [
    "HANDSHAKE", "HANDSHAKE", "ESTABLISHED", "ESTABLISHED", "ESTABLISHED", "CLOSING",
]
parsed_flow = parsed_events[-1]["flow"]
assert parsed_flow["packet_count"] == 6
assert parsed_flow["forward_packet_count"] == 4
assert parsed_flow["backward_packet_count"] == 2
assert parsed_flow["SYN_count"] == 2
assert parsed_flow["ACK_count"] == 5
assert parsed_flow["FIN_count"] == 1
assert parsed_flow["RST_count"] == 0
assert abs(parsed_flow["duration"] - 5.0) < 0.000001


# Check priority and safe fallbacks independently of the parser's integer fields.
tracker = FlowTracker(IDSConfig())
size_cases = [
    ({"total_length": 40, "len": 900, "length": 800, "packet_length": 700}, 20, 40),
    ({"total_length": "60"}, 20, 60),
    ({"total_length": 0}, 20, 0),
    ({"len": 60, "length": 80}, 20, 60),
    ({"length": "52", "packet_length": 80}, 20, 52),
    ({"packet_length": 100}, 48, 100),
    ({}, "48", 48),
    (None, 48, 48),
    ({}, None, 0),
    ({}, "invalid", 0),
    ({}, -1, 0),
    ({}, float("inf"), 0),
    ({}, float("nan"), 0),
    ({}, True, 0),
    ({}, 1.5, 0),
]
for invalid in (None, "invalid", -1, -0.5, 1.5, True, float("inf"), float("nan")):
    size_cases.extend([
        ({"total_length": invalid, "len": 60}, 20, 60),
        ({"total_length": invalid, "len": None, "length": "invalid", "packet_length": -1}, 20, 20),
    ])
for network, payload_length, expected in size_cases:
    assert tracker._get_packet_size({
        "network": network,
        "transport": {"payload_length": payload_length},
    }) == expected, (network, payload_length, expected)
assert tracker._get_packet_size({}) == 0
assert tracker._get_packet_size({"network": None, "transport": None}) == 0

print("T13 legacy fixture PASS: 444 bytes (forward 264, backward 180)")
print("T13 BaiTap1 parser schema PASS: SYN 40 bytes; total 356 (forward 208, backward 148)")
print("T13 length priority and invalid-value fallbacks PASS")
print("T13 PASS")
