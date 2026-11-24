"""Verify independent alerts, normalized allowlists and stream isolation."""

from copy import deepcopy
import json
from pathlib import Path
import sys
from unittest.mock import patch
from uuid import UUID, uuid4


sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from alert import AlertFilterConfig, AlertManager


def event(**changes) -> dict:
    source = dict(timestamp=1000.0, sid=46006, rev=1, msg="Independent alert",
                  src_ip="192.0.2.10", src_port=50000, dst_ip="198.51.100.20", dst_port=80,
                  protocol="TCP", application_protocol="HTTP", flow_id="tc06-flow",
                  priority=2, classtype="web-application-attack",
                  match_information=[{"field": "transport.payload_hex", "start": 0, "end": 2,
                                      "matched_hex": "00ff", "option_index": 1}])
    source.update(changes)
    return source


def main() -> None:
    if not __debug__:
        raise RuntimeError("Run without -O")
    assertions = scenarios = 0

    def check(condition, message):
        nonlocal assertions
        assert condition, message
        assertions += 1

    def verify(alert, source):
        check(UUID(alert.alert_id).version == 4, "Expected UUID4")
        for field in ("sid", "rev", "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
                      "application_protocol", "flow_id", "priority", "classtype"):
            check(getattr(alert, field) == source[field], f"Lost {field}")
        check(alert.message == source["msg"] and alert.severity == ("CRITICAL" if source["priority"] == 1 else "HIGH"), "Wrong message/severity")
        check(alert.timestamp == alert.first_seen == alert.last_seen == float(source["timestamp"]), "Timestamp cursor leaked")
        check(alert.count == 1, "Implicit aggregation")
        check(list(alert.match_information) == source["match_information"], "Match evidence lost")
        check(json.loads(json.dumps(alert.to_dict(), allow_nan=False)) == alert.to_dict(), "Non-JSON alert")

    config = AlertFilterConfig(minimum_severity="MEDIUM", suppressed_sids={46999})
    manager = AlertManager(filter_config=config)
    pairs = (
        ("different SID", event(), event(sid=46007)),
        ("same SID different source", event(), event(src_ip="192.0.2.11")),
        ("same SID different destination", event(), event(dst_ip="198.51.100.21")),
        ("different timestamp", event(), event(timestamp=2000.0)),
        ("identical events remain independent", event(), event()),
        ("same SID different revision", event(), event(rev=2)),
        ("different flow and evidence", event(), event(flow_id="other-flow", match_information=[{
            "field": "flow.state", "start": None, "end": None, "matched_hex": None, "option_index": None,
        }])),
    )
    for name, first, second in pairs:
        before = deepcopy((first, second))
        results = [manager.process(source) for source in (first, second)]
        check(all(r.status == "created" and r.reason is None for r in results), name)
        alerts = [r.alert for r in results]
        check(alerts[0] is not alerts[1] and alerts[0].alert_id != alerts[1].alert_id, "Alerts merged")
        verify(alerts[0], first)
        verify(alerts[1], second)
        check((first, second) == before, "Source mutated")
        original_second = deepcopy(alerts[1].match_information)
        alerts[0].match_information[0]["field"] = "changed"
        check(alerts[1].match_information == original_second, "Alerts share mutable evidence")
        check((first, second) == before, "Alert mutation leaked into source")
        scenarios += 1
        print(f"PASS {name}: two UUID4 alerts; count=1; source/evidence isolated")

    sources = []
    for index in range(100):
        source = event(timestamp=1000.0 + index, flow_id=f"tc06-flow-{index}")
        if index % 5 == 1:
            source["priority"] = 4
        elif index % 5 == 2:
            source.update(sid=46999, priority=1)
        elif index % 5 == 3:
            source["sid"] = "46006"
        elif index % 5 == 4:
            source.update(sid=46007, priority=1)
        sources.append(source)
    before = deepcopy(sources)
    with patch("alert.models.uuid4", wraps=uuid4) as identifiers:
        results = [manager.process(source) for source in sources]
        check(identifiers.call_count == 40, "Blocked events consumed UUIDs")
    expected = ["created", "filtered", "suppressed", "rejected", "created"] * 20
    check([r.status for r in results] == expected, "Stream status/state contamination")
    ids = []
    for result, source, status in zip(results, sources, expected):
        if status == "created":
            verify(result.alert, source)
            ids.append(result.alert.alert_id)
        else:
            check(result.alert is None and isinstance(result.reason, str) and result.reason, "Wrong non-created contract")
    check(len(ids) == len(set(ids)) == 40, "Duplicate stream alerts")
    check(sources == before and manager.filter_config is config, "Stream mutated inputs/configuration")
    scenarios += len(sources)

    policies = (
        ("unrestricted None", AlertFilterConfig(), event(), "created", None),
        ("empty source denies all", AlertFilterConfig(allowed_src_ips=set()), event(), "filtered", "src_ip"),
        ("empty destination denies all", AlertFilterConfig(allowed_dst_ips=[]), event(), "filtered", "dst_ip"),
        ("empty protocols deny all", AlertFilterConfig(allowed_protocols=()), event(), "filtered", "protocol"),
        ("source exact", AlertFilterConfig(allowed_src_ips={"192.0.2.10"}), event(), "created", None),
        ("source mismatch", AlertFilterConfig(allowed_src_ips={"192.0.2.11"}), event(), "filtered", "src_ip"),
        ("destination exact", AlertFilterConfig(allowed_dst_ips={"198.51.100.20"}), event(), "created", None),
        ("destination mismatch", AlertFilterConfig(allowed_dst_ips={"198.51.100.21"}), event(), "filtered", "dst_ip"),
        ("protocol match", AlertFilterConfig(allowed_protocols={" tcp "}), event(protocol=" tcp "), "created", None),
        ("protocol mismatch", AlertFilterConfig(allowed_protocols={"UDP"}), event(), "filtered", "protocol"),
        ("all normalized selectors", AlertFilterConfig(allowed_src_ips={" 192.0.2.10 "}, allowed_dst_ips={"198.51.100.20"}, allowed_protocols={"tcp"}), event(src_ip=" 192.0.2.10 ", protocol="tcp"), "created", None),
        ("UDP allowed", AlertFilterConfig(allowed_protocols={"UDP"}), event(protocol="UDP", application_protocol="DNS"), "created", None),
    )
    for name, policy, source, expected_status, reason_field in policies:
        original = deepcopy(source)
        selected = AlertManager(filter_config=policy)
        with patch("alert.models.uuid4", wraps=uuid4) as identifiers:
            result = selected.process(source)
            check(identifiers.call_count == (1 if expected_status == "created" else 0), name)
        check(result.status == expected_status, (name, result))
        check(source == original, "Allowlist mutated source")
        if expected_status == "filtered":
            check(result.alert is None and result.reason == f"{reason_field} is not allowed by filter policy", name)
        else:
            check(result.alert.protocol == source["protocol"].strip().upper(), "Filtering preceded normalization")
            check(result.alert.src_ip == source["src_ip"].strip(), "IP normalization lost")
        scenarios += 1
    srcs, dsts, protocols = ["192.0.2.10"], ["198.51.100.20"], ["tcp", "TCP"]
    policy = AlertFilterConfig(allowed_src_ips=srcs, allowed_dst_ips=dsts, allowed_protocols=protocols)
    srcs.clear()
    dsts.clear()
    protocols.clear()
    check(policy.allowed_src_ips == frozenset({"192.0.2.10"}) and policy.allowed_dst_ips == frozenset({"198.51.100.20"}), "IP configuration aliases caller")
    check(policy.allowed_protocols == frozenset({"TCP"}), "Protocol config not normalized/deduplicated")
    scenarios += 1
    for name, value in (
        ("allowed_src_ips", "192.0.2.10"), ("allowed_src_ips", [123]),
        ("allowed_src_ips", ["999.0.0.1"]), ("allowed_src_ips", ["192.0.2.0/24"]),
        ("allowed_dst_ips", ["2001:db8::1"]), ("allowed_dst_ips", {}),
        ("allowed_protocols", "TCP"), ("allowed_protocols", ["ICMP"]),
        ("allowed_protocols", [True]), ("allowed_protocols", [None]),
    ):
        try:
            AlertFilterConfig(**{name: value})
        except ValueError as exc:
            check(name in str(exc), "Unclear allowlist config error")
        else:
            raise AssertionError(f"Invalid {name} accepted: {value}")
        scenarios += 1
    print("PASS 100-event stream: 40 created, 20 filtered, 20 suppressed, 20 rejected; 40 UUIDs")
    print("PASS optional exact-IP/protocol policies: normalized comparisons, None/empty semantics and config snapshots")
    print(f"TC06 PASS: {scenarios} scenarios; {assertions} assertions")


if __name__ == "__main__":
    main()
