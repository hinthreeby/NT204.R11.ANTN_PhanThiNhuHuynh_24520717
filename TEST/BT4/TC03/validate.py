"""Verify safe rejection, nullable fields and recovery after malformed input."""

from copy import deepcopy
import json
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from alert import AlertManager


def event() -> dict:
    return dict(timestamp=1000.0, sid=43003, rev=1, msg="Validation input",
                src_ip="192.0.2.1", src_port=12345, dst_ip="198.51.100.2", dst_port=80,
                protocol="TCP", application_protocol="UNKNOWN", flow_id="flow-validation",
                match_information=[{"field": "transport.payload_hex", "start": 0, "end": 2,
                                    "matched_hex": "00ff", "option_index": 1}])


def main() -> None:
    if not __debug__:
        raise RuntimeError("Run without -O")
    assertions = 0

    def check(condition, message):
        nonlocal assertions
        assert condition, message
        assertions += 1

    cases = [("top-level input", source, "dictionary") for source in (None, [], (), "text", 1, True)]
    for field in event():
        source = event()
        del source[field]
        cases.append((f"missing {field}", source, field))
        if field != "flow_id":
            source = event()
            source[field] = None
            cases.append((f"null {field}", source, field))
    invalid_values = {
        "timestamp": [-1, float("nan"), float("inf"), float("-inf"), True, "1000", [], 10 ** 1000],
        "sid": [True, False, 0, -1, 1.5, "43003"],
        "rev": [True, 0, -1, "1", 1.5],
        "msg": ["", "   ", 1, []],
        "src_ip": ["999.0.0.1", "2001:db8::1", "192.0.2.0/24", 123, ""],
        "dst_ip": ["bad-ip", "1.2.3", [], ""],
        "src_port": [True, -1, 65536, 10.75, "80"],
        "dst_port": [False, -1, 65536, 80.5, 65535.9, "80"],
        "protocol": ["ICMP", "", 1, []],
        "application_protocol": ["TLS", "", {}, True],
        "flow_id": ["", "   ", 1, []],
        "priority": [True, 0, -1, 1.5, "1", float("nan"), float("inf")],
        "classtype": ["", "  ", 1, []],
        "match_information": [[], {}, "content", [None], [{"field": ""}]],
    }
    for field, values in invalid_values.items():
        for value in values:
            source = event()
            source[field] = value
            cases.append((f"invalid {field}", source, field))
    for field, value in (
        ("start", -1), ("start", True), ("end", 1), ("end", None),
        ("matched_hex", "zz"), ("matched_hex", "00"), ("matched_hex", b"00ff"),
        ("option_index", -1), ("option_index", True),
    ):
        source = event()
        source["match_information"][0][field] = value
        cases.append((f"invalid evidence {field}", source, "match_information"))
    manager = AlertManager()
    for name, source, reason_field in cases:
        before = json.dumps(source, sort_keys=True, default=repr)
        result = manager.process(source)
        check(result.status == "rejected" and result.alert is None, f"{name}: invalid source created alert")
        check(isinstance(result.reason, str) and reason_field in result.reason, f"{name}: unclear reason {result.reason}")
        check(json.dumps(source, sort_keys=True, default=repr) == before, f"{name}: source mutated")
        valid = manager.process(event())
        check(valid.status == "created" and valid.reason is None, f"{name}: later valid input failed")
        check(valid.alert.sid == 43003 and valid.alert.count == 1, f"{name}: previous event leaked state")

    valid_cases = []
    source = event()
    source.update(flow_id=None, priority=None, classtype=None)
    valid_cases.append(("allowed nulls", source))
    valid_cases.append(("optional fields absent", event()))
    source = event()
    source.update(timestamp=0, protocol="udp", application_protocol="dns")
    source.update(src_port=0, dst_port=65535)
    valid_cases.append(("time/port boundaries and UDP normalization", source))
    source = event()
    source["match_information"] = [{"field": "flow.state"}]
    valid_cases.append(("non-content evidence", source))
    for name, source in valid_cases:
        original = deepcopy(source)
        result = manager.process(source)
        check(result.status == "created" and result.reason is None, f"{name}: valid source rejected")
        check(result.alert.flow_id == source["flow_id"], f"{name}: flow identity changed")
        check(source == original, f"{name}: source mutated")
        check(json.loads(json.dumps(result.alert.to_dict(), allow_nan=False)) == result.alert.to_dict(), name)
    print(f"PASS {len(cases)} malformed/missing cases: explicit rejection, source preserved, next valid event accepted")
    print("PASS nullable flow_id/priority/classtype, optional fields, time/port boundaries and non-content evidence")
    print(f"TC03 PASS: {len(cases) + len(valid_cases)} scenarios; {assertions} assertions")


if __name__ == "__main__":
    main()
