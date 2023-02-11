from .models import DomainNameHelper, Zone, generate_domain_from_int
from .test_utils import WithUserTests
from django.test import TestCase
from django.utils import timezone


class DomainNameHelperTests(TestCase):
    def test_increasing_names(self):
        last = None
        for _ in range(1000):
            curr = DomainNameHelper.objects.create()
            if last is not None:
                self.assertLess(last.id, curr.id)
                self.assertTrue(
                    len(last.get_name()) < len(curr.get_name())
                    or last.get_name() < curr.get_name()
                )
            last = curr


class GeneratedDomainName(TestCase):
    def test_specific_values(self):
        self.assertEqual(generate_domain_from_int(0), "0")
        self.assertEqual(generate_domain_from_int(1), "1")
        self.assertEqual(generate_domain_from_int(35), "z")
        self.assertEqual(generate_domain_from_int(36), "00")
        self.assertEqual(generate_domain_from_int(36 * 36 + 36), "000")
        self.assertEqual(generate_domain_from_int(36 * 36 * 36 + 36 * 36 + 36), "0000")
        self.assertEqual(generate_domain_from_int(36 * 36 * 36 + 36 * 36 + 35), "zzz")

    def test_zero_domains(self):
        for i in range(2, 63):
            first_index = 0
            for k in range(1, i):
                first_index += 36**k
            expected = "0" * i
            actual = generate_domain_from_int(first_index)
            self.assertEqual(expected, actual)

            expected = "z" * (i - 1)
            actual = generate_domain_from_int(first_index - 1)
            self.assertEqual(expected, actual)

    def test_has_ordered_domains(self):
        previous = ""
        for i in range(1_000_000):
            domain = generate_domain_from_int(i)
            if len(previous) == len(domain):
                self.assertLess(previous, domain)
            else:
                self.assertLess(len(previous), len(domain))
            previous = domain


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
