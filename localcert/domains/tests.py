from django.test import TestCase

from .models import generate_domain_from_int


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
            print(expected, actual)
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
