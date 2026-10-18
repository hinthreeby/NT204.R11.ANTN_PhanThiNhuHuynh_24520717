import json
from pathlib import Path


events_path = Path(__file__).resolve().parent / "events.jsonl"
with events_path.open(encoding="utf-8") as source:
    events = [json.loads(line) for line in source if line.strip()]

assert len(events) == 1
event = events[0]
application = event["application"]
assert application["protocol"] == "HTTP"
assert application["type"] == "request"
assert application["raw_uri"] == "/login?id=%27%20OR%201%3D1"
assert application["decoded_uri"] == "/login?id=' OR 1=1"
assert application["decode_status"] == "success"
assert event["decoder"]["status"] == "success"

print("T01 PASS")
