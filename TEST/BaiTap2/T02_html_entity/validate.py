import json
from pathlib import Path


events_path = Path(__file__).resolve().parent / "events.jsonl"
with events_path.open(encoding="utf-8") as source:
    events = [json.loads(line) for line in source if line.strip()]

assert len(events) == 1
event = events[0]
application = event["application"]
assert application["protocol"] == "HTTP"
assert application["type"] == "response"
assert application["body"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
assert application["raw_body"] == "&lt;script&gt;alert(1)&lt;/script&gt;"
assert application["decoded_text"] == "<script>alert(1)</script>"
assert application["decode_status"] == "success"
assert event["decoder"]["status"] == "success"

print("T02 PASS")
