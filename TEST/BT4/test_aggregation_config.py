"""Stage 1 configuration checks, separate from the existing BT4 cases.

Run from the repository root:
    python -B -m unittest discover -s TEST/BT4 -p test_aggregation_config.py -v
"""

from dataclasses import FrozenInstanceError
import unittest

from alert import AggregationConfig


class AggregationConfigTests(unittest.TestCase):
    def test_defaults(self):
        config = AggregationConfig()
        self.assertIs(config.enabled, False)
        self.assertEqual(config.window_seconds, 60)
        self.assertIs(type(config.window_seconds), int)

    def test_custom_config(self):
        for enabled in (False, True):
            for window in (1, 30, 120):
                with self.subTest(enabled=enabled, window=window):
                    config = AggregationConfig(enabled=enabled, window_seconds=window)
                    self.assertIs(config.enabled, enabled)
                    self.assertEqual(config.window_seconds, window)

    def test_invalid_enabled(self):
        for enabled in (0, 1, None, "true", [], {}):
            with self.subTest(enabled=enabled):
                with self.assertRaisesRegex(ValueError, "enabled"):
                    AggregationConfig(enabled=enabled)

    def test_invalid_window_even_when_disabled(self):
        for enabled in (False, True):
            for window in (True, False, 0, -1, 60.0, 1.5, "60", None,
                           float("nan"), float("inf"), [], {}):
                with self.subTest(enabled=enabled, window=window):
                    with self.assertRaisesRegex(ValueError, "window_seconds"):
                        AggregationConfig(enabled=enabled, window_seconds=window)

    def test_immutable(self):
        config = AggregationConfig()
        for name, value in (("enabled", True), ("window_seconds", 120)):
            with self.subTest(field=name):
                with self.assertRaises(FrozenInstanceError):
                    setattr(config, name, value)
                with self.assertRaises(FrozenInstanceError):
                    delattr(config, name)
        self.assertIs(config.enabled, False)
        self.assertEqual(config.window_seconds, 60)


if __name__ == "__main__":
    unittest.main()
