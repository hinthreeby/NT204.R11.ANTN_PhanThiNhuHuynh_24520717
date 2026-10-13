import json
from pathlib import Path


path = Path(
    "TEST/T05_normalization/events.jsonl"
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


http_event = events[0]

assert (
    http_event["network"]["protocol"]
    == "IPv4"
)

assert (
    http_event["transport"]["protocol"]
    == "TCP"
)

assert (
    http_event["transport"]["src_port"]
    == 50000
)

assert (
    http_event["application"]["protocol"]
    == "HTTP"
)

assert (
    http_event["application"]["headers"]["host"]
    == "example.com"
)

assert (
    "content-type"
    in http_event["application"]["headers"]
)

assert (
    http_event["application"]["normalized_uri"]
    == "/Index"
)

assert (
    http_event["preprocess_status"]
    == "valid"
)


dns_event = events[1]

assert (
    dns_event["transport"]["protocol"]
    == "UDP"
)

assert (
    dns_event["application"]["protocol"]
    == "DNS"
)

assert (
    dns_event["application"]["domain"]
    == "example.com"
)

assert (
    dns_event["preprocess_status"]
    == "valid"
)


print("T05 PASS")