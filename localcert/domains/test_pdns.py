from django.test import TestCase
from .pdns import pdns_get_stats


class TestPdns(TestCase):
    def test_pdns_has_stats(self):
        stats = pdns_get_stats()
        self.assertTrue(len(stats) > 0)
        self.assertIn("name", stats[0])
        self.assertIn("value", stats[0])
