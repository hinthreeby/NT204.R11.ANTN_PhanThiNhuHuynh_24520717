"""Stage 3 integration checks; existing BT4 tests remain unchanged.

python -B -m unittest discover -s TEST/BT4 -p test_manager_aggregation.py -v
"""

from copy import deepcopy
import unittest
from unittest.mock import patch

from alert import AggregationConfig, AlertFilterConfig, AlertManager, AlertResult, SeverityConfig
from alert.aggregation import AlertGroup as EngineAlertGroup
from alert.models import AlertGroup


def detection(timestamp=100, **changes):
    source = dict(timestamp=timestamp, sid=31, rev=1, msg="HTTP match", priority=2,
                  classtype="web-application-attack", src_ip="192.0.2.1", src_port=53000,
                  dst_ip="198.51.100.2", dst_port=80, protocol="TCP",
                  application_protocol="HTTP", flow_id="flow-a",
                  match_information=[dict(field="payload", start=0, end=1,
                                          matched_hex="FF", option_index=0)])
    source.update(changes)
    return source


def manager(**kwargs):
    return AlertManager(aggregation_config=AggregationConfig(enabled=True, window_seconds=60),
                        **kwargs)


class ManagerAggregationTests(unittest.TestCase):
    def test_disabled_and_positional_severity_config_compatibility(self):
        severity = SeverityConfig({2: "CRITICAL"})
        for config in (None, AggregationConfig(enabled=False, window_seconds=1)):
            with self.subTest(config=config):
                instance = AlertManager(severity, aggregation_config=config)
                with patch("alert.manager.AlertAggregator.process",
                           side_effect=AssertionError("Disabled engine must not process")):
                    first = instance.process(detection())
                    second = instance.process(detection())
                self.assertEqual((first.status, second.status), ("created", "created"))
                self.assertNotEqual(first.alert.alert_id, second.alert.alert_id)
                for result in (first, second):
                    self.assertEqual(result.alert.count, 1)
                    self.assertEqual(result.alert.severity, "CRITICAL")
                    self.assertIsNone(result.group)
                    self.assertEqual(result.finalized, ())
                self.assertEqual(instance.flush(), ())
        old_result = AlertResult("rejected", None, "invalid")
        self.assertIsNone(old_result.group)
        self.assertEqual(old_result.finalized, ())
        self.assertIs(EngineAlertGroup, AlertGroup)

    def test_new_group_merge_and_stable_id(self):
        instance = manager()
        first = instance.process(detection())
        second = instance.process(detection(120))
        self.assertEqual(first.status, "created")
        self.assertIs(first.alert, first.group.summary)
        self.assertEqual(first.alert.count, 1)
        self.assertEqual(first.alert.alert_id, first.group.members[0].alert_id)
        self.assertEqual(second.status, "aggregated")
        self.assertIsNone(second.reason)
        self.assertEqual(second.alert.alert_id, first.alert.alert_id)
        self.assertEqual(second.alert.count, 2)
        self.assertEqual(second.alert.first_seen, 100)
        self.assertEqual(second.alert.last_seen, 120)
        self.assertEqual(second.finalized, ())
        self.assertEqual(len(second.group.members), 2)
        self.assertEqual(first.alert.count, 1)

    def test_boundary_expiry_and_flush_handoff(self):
        instance = manager()
        instance.process(detection())
        boundary = instance.process(detection(160))
        self.assertEqual(boundary.status, "aggregated")
        expired = instance.process(detection(161))
        self.assertEqual(expired.status, "created")
        self.assertEqual(expired.finalized, (boundary.group,))
        self.assertNotEqual(expired.alert.alert_id, boundary.alert.alert_id)
        self.assertEqual(expired.alert.count, 1)
        self.assertEqual(expired.alert.first_seen, 161)
        self.assertEqual(expired.alert.last_seen, 161)
        self.assertEqual(instance.flush(), (expired.group,))
        self.assertEqual(instance.flush(), ())

    def test_blocked_events_never_enter_engine_or_advance_time(self):
        policy = AlertFilterConfig(minimum_severity="HIGH", suppressed_sids={99},
                                   allowed_src_ips={"192.0.2.1"})
        cases = (
            (detection(1000, priority=0), "rejected"),
            (detection(1000, priority=4), "filtered"),
            (detection(1000, sid=99), "suppressed"),
            (detection(1000, src_ip="192.0.2.3"), "filtered"),
            (detection(1000, sid=99, priority=0), "rejected"),
        )
        for source, status in cases:
            with self.subTest(status=status, source=source):
                instance = manager(filter_config=policy)
                opened = instance.process(detection())
                before = deepcopy(source)
                with patch("alert.manager.AlertAggregator.process",
                           side_effect=AssertionError("Blocked event entered engine")), \
                     patch("alert.models.uuid4",
                           side_effect=AssertionError("Blocked event allocated UUID")):
                    result = instance.process(source)
                self.assertEqual(result.status, status)
                self.assertIsNone(result.alert)
                self.assertIsNone(result.group)
                self.assertEqual(result.finalized, ())
                self.assertTrue(result.reason)
                self.assertEqual(source, before)
                followup = instance.process(detection(160))
                self.assertEqual(followup.status, "aggregated")
                self.assertEqual(followup.alert.alert_id, opened.alert.alert_id)
                self.assertEqual(followup.alert.count, 2)
                self.assertEqual(instance.flush(), (followup.group,))

    def test_normalization_and_severity_precede_aggregation(self):
        severity = SeverityConfig({2: "CRITICAL"})
        instance = manager(config=severity,
                           filter_config=AlertFilterConfig(minimum_severity="CRITICAL",
                                                          allowed_protocols={"TCP"}))
        first = instance.process(detection(src_ip=" 192.0.2.1 ", protocol=" tcp "))
        second = instance.process(detection(110))
        self.assertEqual(second.status, "aggregated")
        self.assertEqual(first.alert.severity, "CRITICAL")
        self.assertEqual(second.alert.alert_id, first.alert.alert_id)
        self.assertEqual(second.group.members[0].src_ip, "192.0.2.1")
        self.assertEqual(second.group.members[0].protocol, "TCP")

    def test_all_source_metadata_preserved_and_no_aliases(self):
        instance = manager()
        sources = [detection(), detection(110, flow_id="flow-b", rev=2,
                    msg="different match", priority=1, src_port=54000, dst_port=8080,
                    classtype=None, match_information=[dict(field="flow.state")])]
        originals = deepcopy(sources)
        first = instance.process(sources[0])
        result = instance.process(sources[1])
        self.assertEqual(sources, originals)
        self.assertEqual(result.alert.flow_id, "flow-a")
        self.assertEqual(result.alert.rev, 1)
        self.assertEqual(result.alert.match_information, first.alert.match_information)
        for member, source in zip(result.group.members, originals):
            for field in ("flow_id", "rev", "src_port", "dst_port", "priority", "classtype"):
                self.assertEqual(getattr(member, field), source[field])
            self.assertEqual(member.message, source["msg"])
        self.assertEqual(result.group.members[1].severity, "CRITICAL")
        self.assertEqual(result.group.members[1].match_information[0]["field"], "flow.state")
        self.assertEqual(result.group.members[0].match_information[0]["matched_hex"], "ff")
        sources[0]["match_information"][0]["field"] = "source mutation"
        first.alert.match_information[0]["field"] = "old view mutation"
        result.group.members[1].match_information[0]["field"] = "new view mutation"
        flushed = instance.flush()[0]
        self.assertEqual(flushed.members[0].match_information[0]["field"], "payload")
        self.assertEqual(flushed.members[1].match_information[0]["field"], "flow.state")

    def test_late_event_finalized_once_and_open_group_preserved(self):
        instance = manager()
        opened = instance.process(detection())
        late = instance.process(detection(99))
        self.assertEqual(late.status, "finalized")
        self.assertEqual(late.finalized, (late.group,))
        self.assertIs(late.alert, late.group.summary)
        self.assertEqual(late.alert.count, 1)
        self.assertNotEqual(late.alert.alert_id, opened.alert.alert_id)
        self.assertEqual(instance.flush(), (opened.group,))
        self.assertEqual(instance.flush(), ())

    def test_out_of_order_in_open_window(self):
        instance = manager()
        instance.process(detection())
        instance.process(detection(150))
        result = instance.process(detection(110))
        self.assertEqual(result.status, "aggregated")
        self.assertEqual(result.alert.count, 3)
        self.assertEqual(result.alert.first_seen, 100)
        self.assertEqual(result.alert.last_seen, 150)

    def test_different_keys_and_multiple_finalizations(self):
        instance = manager()
        first = instance.process(detection())
        other = instance.process(detection(101, sid=32))
        result = instance.process(detection(200, dst_ip="198.51.100.3"))
        self.assertEqual(other.status, "created")
        self.assertNotEqual(other.alert.alert_id, first.alert.alert_id)
        self.assertEqual(result.finalized, (first.group, other.group))
        self.assertEqual(instance.flush(), (result.group,))

    def test_config_validation_and_readonly_policy(self):
        for config in ({}, False, 1):
            with self.assertRaisesRegex(TypeError, "AggregationConfig"):
                AlertManager(aggregation_config=config)
        instance = manager()
        self.assertTrue(instance.aggregation_config.enabled)
        with self.assertRaises(AttributeError):
            instance.aggregation_config = AggregationConfig()


if __name__ == "__main__":
    unittest.main()
