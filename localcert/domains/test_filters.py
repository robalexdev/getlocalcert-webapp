from .templatetags.extra_filters import namedDuration
from django.test import TestCase


class TestNamedDuration(TestCase):
    def test_named_duration(self):
        self.assertEqual(namedDuration(1), "1 second")
        self.assertEqual(namedDuration(2), "2 seconds")
        self.assertEqual(namedDuration(59), "59 seconds")
        self.assertEqual(namedDuration(60), "1 minute")
        self.assertEqual(namedDuration(61), "61 seconds")
        self.assertEqual(namedDuration(120), "2 minutes")
        self.assertEqual(namedDuration(3600), "1 hour")
        self.assertEqual(namedDuration(86400), "1 day")
