"""Small standalone stage 2 checks; no AlertManager or TC07/TC08 fixtures.

python -B -m unittest discover -s TEST/BT4 -p test_aggregation.py -v
"""

from copy import deepcopy
from dataclasses import replace
import unittest

from alert import AggregationConfig, Alert, AlertResult
from alert.aggregation import AlertAggregator, AggregationCapacityError


def event(timestamp=100.0, **changes):
    fields = dict(timestamp=timestamp, sid=17, rev=1, message="match", severity="HIGH",
                  src_ip="192.0.2.1", src_port=1234, dst_ip="198.51.100.2", dst_port=80,
                  protocol="TCP", application_protocol="HTTP", flow_id="flow-a",
                  first_seen=timestamp, last_seen=timestamp, priority=2, classtype="web",
                  match_information=({"field": "payload", "matched_hex": "ff"},))
    fields.update(changes)
    return Alert(**fields)


def engine(**limits):
    return AlertAggregator(AggregationConfig(enabled=True, window_seconds=60), **limits)


class AlertAggregationTests(unittest.TestCase):
    def test_new_group(self):
        aggregator = engine()
        source = event()
        result = aggregator.process(source)
        self.assertEqual(result.status, "created")
        self.assertEqual(result.group.summary, source)
        self.assertEqual(result.group.members, (source,))
        self.assertEqual(result.finalized, ())
        self.assertEqual(aggregator.active_group_count, 1)

    def test_merge_metadata_and_input_output_isolation(self):
        aggregator = engine()
        first = event()
        second = event(120, flow_id="flow-b", rev=2, message="changed", severity="LOW",
                       src_port=4321, dst_port=8080, priority=4, classtype=None,
                       protocol="UDP", application_protocol="DNS",
                       match_information=({"field": "dns", "matched_hex": "00"},))
        original = deepcopy((first, second))
        view = aggregator.process(first)
        first.match_information[0]["field"] = "caller edit"
        view.group.summary.match_information[0]["field"] = "view edit"
        result = aggregator.process(second)
        self.assertEqual(result.status, "merged")
        self.assertEqual(result.group.summary,
                         replace(original[0], count=2, last_seen=120))
        self.assertEqual(result.group.members, original)
        self.assertEqual(second, original[1])
        result.group.members[1].match_information[0]["field"] = "output edit"
        self.assertEqual(aggregator.flush()[0].members, original)

    def test_different_keys(self):
        aggregator = engine()
        sources = (event(), event(sid=18), event(src_ip="192.0.2.3"),
                   event(dst_ip="198.51.100.4"))
        for source in sources:
            self.assertEqual(aggregator.process(source).status, "created")
        self.assertEqual(aggregator.active_group_count, 4)
        self.assertEqual(len(aggregator.flush()), 4)

    def test_custom_window(self):
        aggregator = AlertAggregator(AggregationConfig(enabled=True, window_seconds=2))
        aggregator.process(event(0))
        boundary = aggregator.process(event(2))
        self.assertEqual(boundary.status, "merged")
        expired = aggregator.process(event(2.25))
        self.assertEqual(expired.status, "created")
        self.assertEqual(expired.finalized, (boundary.group,))

    def test_boundary_fixed_window_and_expired_group(self):
        aggregator = engine()
        first = event()
        aggregator.process(first)
        aggregator.process(event(150))
        boundary = aggregator.process(event(160))
        self.assertEqual(boundary.status, "merged")
        self.assertEqual(boundary.group.summary.count, 3)
        self.assertEqual(boundary.group.summary.first_seen, 100)
        # Reusing the source ID must still create a distinct replacement ID.
        result = aggregator.process(replace(first, timestamp=161))
        self.assertEqual(result.status, "created")
        self.assertEqual(result.finalized, (boundary.group,))
        self.assertNotEqual(result.group.summary.alert_id, first.alert_id)
        self.assertEqual(result.group.summary.count, 1)
        self.assertEqual(result.group.summary.first_seen, 161)
        self.assertEqual(result.group.summary.last_seen, 161)

    def test_out_of_order_inside_and_before_first_seen(self):
        aggregator = engine()
        first = aggregator.process(event()).group
        aggregator.process(event(150))
        result = aggregator.process(event(110))
        self.assertEqual(result.status, "merged")
        self.assertEqual(result.group.summary.count, 3)
        self.assertEqual(result.group.summary.last_seen, 150)
        late = aggregator.process(event(99))
        self.assertEqual(late.status, "late")
        self.assertEqual(late.finalized, (late.group,))
        self.assertEqual(late.group.summary.count, 1)
        self.assertNotEqual(late.group.summary.alert_id, first.summary.alert_id)
        self.assertEqual(aggregator.flush(), (result.group,))

    def test_expire_other_keys_and_never_reopen_closed_groups(self):
        aggregator = engine()
        old = aggregator.process(event()).group
        result = aggregator.process(event(200, sid=18))
        self.assertEqual(result.finalized, (old,))
        self.assertEqual(aggregator.active_group_count, 1)
        late = aggregator.process(event(120))
        self.assertEqual(late.status, "late")
        self.assertEqual(late.finalized, (late.group,))
        self.assertEqual(aggregator.active_group_count, 1)
        self.assertEqual(aggregator.flush(), (result.group,))

    def test_flush_cleans_state_but_preserves_watermark(self):
        aggregator = engine()
        group = aggregator.process(event()).group
        self.assertEqual(aggregator.flush(), (group,))
        self.assertEqual(aggregator.active_group_count, 0)
        self.assertEqual(aggregator.flush(), ())
        self.assertEqual(aggregator.process(event(90)).status, "late")
        self.assertEqual(aggregator.active_group_count, 0)
        self.assertEqual(aggregator.process(event(100)).status, "created")

    def test_disabled_passthrough(self):
        aggregator = AlertAggregator()
        source = event()
        for _ in range(2):
            result = aggregator.process(source)
            self.assertEqual(result.status, "bypassed")
            self.assertEqual(result.finalized, (result.group,))
            self.assertEqual(result.group.summary, source)
        self.assertEqual(aggregator.active_group_count, 0)
        self.assertEqual(aggregator.flush(), ())

    def test_capacity_is_atomic_and_flush_allows_retry(self):
        aggregator = engine(max_groups=1, max_events_per_group=2)
        aggregator.process(event())
        snapshot = aggregator.process(event(110)).group
        for source in (event(120), event(120, sid=18)):
            with self.assertRaises(AggregationCapacityError):
                aggregator.process(source)
        self.assertEqual(aggregator.flush(), (snapshot,))
        # A failed call at 120 must not advance the watermark from 110.
        self.assertEqual(aggregator.process(event(115)).status, "created")
        aggregator.flush()
        self.assertEqual(aggregator.process(event(120)).status, "created")

    def test_long_stream_cleanup_and_bounded_equal_timestamp_stream(self):
        aggregator = engine(max_groups=2)
        finalized = 0
        for index in range(300):
            result = aggregator.process(event(index * 61, sid=index + 1))
            finalized += len(result.finalized)
            self.assertEqual(aggregator.active_group_count, 1)
        self.assertEqual(finalized + len(aggregator.flush()), 300)
        aggregator = engine(max_groups=2)
        aggregator.process(event(sid=1))
        aggregator.process(event(sid=2))
        with self.assertRaises(AggregationCapacityError):
            aggregator.process(event(sid=3))
        self.assertEqual(len(aggregator.flush()), 2)

    def test_invalid_input_and_constructor(self):
        for config in ({}, False):
            with self.assertRaises(TypeError):
                AlertAggregator(config)
        for name in ("max_groups", "max_events_per_group"):
            for value in (True, 0, -1, 1.5):
                with self.assertRaises(ValueError):
                    engine(**{name: value})
        aggregator = engine()
        snapshot = aggregator.process(event()).group
        for timestamp in (True, -1, float("nan"), float("inf"), "100", 10 ** 1000):
            with self.assertRaises(ValueError):
                aggregator.process(event(timestamp))
        with self.assertRaises(TypeError):
            aggregator.process({})
        for status in ("rejected", "filtered", "suppressed"):
            with self.assertRaises(TypeError):
                aggregator.process(AlertResult(status, None, "blocked"))
        with self.assertRaises(ValueError):
            aggregator.process(event(count=2))
        self.assertEqual(aggregator.flush(), (snapshot,))


if __name__ == "__main__":
    unittest.main()
