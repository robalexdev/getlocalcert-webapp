from .templatetags.extra_filters import namedDuration, strip_quot, parent_zone_name
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


class TestStripQuot(TestCase):
    def test(self):
        self.assertEquals(strip_quot("abc"), "abc")
        self.assertEquals(strip_quot('"abc'), "abc")
        self.assertEquals(strip_quot('abc"'), "abc")
        self.assertEquals(strip_quot('"abc"'), "abc")


class TestParentZoneName(TestCase):
    def test(self):
        self.assertEquals(parent_zone_name("example.localcert.net"), "localcert.net")
        self.assertEquals(parent_zone_name("example.localcert.net."), "localcert.net")
        self.assertEquals(
            parent_zone_name("example.localhostcert.net"), "localhostcert.net"
        )
        self.assertEquals(parent_zone_name("example.corpnet.work"), "corpnet.work")
        self.assertEquals(parent_zone_name("example.unknown.com"), "Zone")
