import json

from config import Bai2Config
from decoder.decoder import Decoder


event = {
    "packet_id": 1,
    "timestamp": 1790000003.0,

    "network": {
        "protocol": "IPv4",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.20",
    },

    "transport": {
        "protocol": "TCP",
        "src_port": 50000,
        "dst_port": 80,
    },

    "application": {
        "protocol": "HTTP",
        "type": "response",
        "headers": {
            "Content-Type": "text/plain"
        },
        "body": b"Hello \xff world",
    },

    "errors": [],
}


decoder = Decoder(
    Bai2Config()
)


result = decoder.process(
    event
)


application = result[
    "application"
]


assert (
    application["decode_status"]
    == "partial"
)

assert (
    "\ufffd"
    in application["decoded_body"]
)


print(
    json.dumps(
        result,
        indent=2,
        ensure_ascii=False,
    )
)

print("T04 PASS")