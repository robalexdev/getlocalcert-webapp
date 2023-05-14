from .models import Zone
from .test_utils import WithUserTests
from django.test import TestCase
from django.utils import timezone


class ModelTests(WithUserTests):
    def test_zone(self):
        expected_fqdn = "abc.localhostcert.net"
        a = Zone.objects.create(
            name=expected_fqdn,
            owner=self.testUser,
        )

        self.assertEqual(expected_fqdn, a.name)
        self.assertEqual(expected_fqdn, str(a))

        original_created = a.created.timestamp()
        original_updated = a.updated.timestamp()

        self.assertAlmostEqual(original_created, original_updated, delta=0.01)
        self.assertAlmostEqual(original_updated, timezone.now().timestamp(), delta=0.01)

        # Update the owner
        a.owner = self.wrongUser
        a.save()

        self.assertLess(original_updated, a.updated.timestamp())
        self.assertEqual(original_created, a.created.timestamp())
