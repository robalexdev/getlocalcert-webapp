import random
from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from django.urls import reverse
from django.conf import settings
from uuid import uuid4
from unittest.mock import patch
from bs4 import BeautifulSoup as bs
from base64 import urlsafe_b64encode
from hashlib import sha256

from .utils import (
    ACME_CHALLENGE_LABEL,
    CustomExceptionBadRequest,
    validate_acme_dns01_txt_value,
)
from .models import (
    generate_domain_from_int,
    Zone,
    DomainNameHelper,
)
from .views import (
    list_zones,
    create_free_domain,
    describe_zone,
    modify_rrset,
    create_resource_record_page,
)


TEN_CHARS = "1234567890"


def randomDns01ChallengeResponse() -> str:
    m = sha256()
    m.update(str(uuid4()).encode("utf-8"))
    return urlsafe_b64encode(m.digest()).decode("utf-8").replace("=", "")


class AlwaysSucceed(TestCase):
    def test_pass(self):
        pass


class ValidateAcmeDnsTxtRecord(TestCase):
    def test_valid_record(self):
        validate_acme_dns01_txt_value(randomDns01ChallengeResponse())

    def test_invalid_record(self):
        # too short
        with self.assertRaisesMessage(CustomExceptionBadRequest, "incorrect length"):
            validate_acme_dns01_txt_value(urlsafe_b64encode(b"123").decode("utf-8"))

        # too long
        with self.assertRaisesMessage(CustomExceptionBadRequest, "incorrect length"):
            validate_acme_dns01_txt_value(
                randomDns01ChallengeResponse() + randomDns01ChallengeResponse()
            )

        # wrong encoding
        with self.assertRaisesMessage(CustomExceptionBadRequest, "base64"):
            validate_acme_dns01_txt_value("abc+")

        # no padding
        with self.assertRaisesMessage(
            CustomExceptionBadRequest, "must not use padding"
        ):
            validate_acme_dns01_txt_value(urlsafe_b64encode(b"1234").decode("utf-8"))


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


class WithMockDomainNameHelper(TestCase):
    def __init__(self, a):
        super().__init__(a)
        self.free_domain_index = random.randint(1_000, 1_000_000_000)

    def setUp(self) -> None:
        super().setUp()
        patcher = patch.object(DomainNameHelper, "get_name", return_value="1")
        self.mock_domainNameHelper = patcher.start()
        self.addCleanup(patcher.stop)

    def _create_free_domain(self, expected_name=None):
        if expected_name is None:
            self.free_domain_index += 1
            self.mock_domainNameHelper.return_value = str(self.free_domain_index)
        else:
            self.mock_domainNameHelper.return_value = expected_name
        resp = self.client.post(reverse(create_free_domain), follow=True)
        redirect = resp.redirect_chain[0][0]
        domain = redirect.replace("/domain/", "").replace("/", "")
        return domain


class WithUserTests(WithMockDomainNameHelper):
    def setUp(self):
        super().setUp()

        self.testUser = User.objects.create(username="a")
        self.wrongUser = User.objects.create(username="b")
        self.request_body = None

    def assert_404_when_logged_in_as_wrong_user_on_get(self):
        self.client.force_login(self.wrongUser)
        response = self.client.get(self.target_url)
        self.assertEqual(404, response.status_code)

    def assert_404_when_logged_in_as_wrong_user_on_post(self):
        self.client.force_login(self.wrongUser)
        response = self.client.post(self.target_url, self.request_body)
        self.assertEqual(404, response.status_code)

    def assert_redirects_to_login_when_logged_out_on_get(self):
        self.client.logout()
        response = self.client.get(self.target_url)
        self.assertRedirects(
            response, "/accounts/login/?next=" + self.target_url, status_code=302
        )

    def assert_redirects_to_login_when_logged_out_on_post(self):
        self.client.logout()
        response = self.client.post(self.target_url, self.request_body)
        self.assertRedirects(
            response, "/accounts/login/?next=" + self.target_url, status_code=302
        )

    def assert_post_method_not_allowed(self):
        response = self.client.post(self.target_url)
        self.assertEqual(response.status_code, 405)

    def assert_get_method_not_allowed(self):
        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 405)

    def assert_head_method_not_allowed(self):
        response = self.client.head(self.target_url)
        self.assertEqual(response.status_code, 405)


class WithZoneTests(WithUserTests):
    def setUp(self):
        super().setUp()
        name = str(uuid4())
        self.mock_domainNameHelper.return_value = name
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(create_free_domain),
            follow=True,
        )
        self.assertContains(response, name)
        zones = Zone.objects.all()
        zones = [_ for _ in zones]
        assert len(zones) == 1, f"Found {len(zones)} zones."
        self.zone = zones[0]

        self.rr_name = f"{ACME_CHALLENGE_LABEL}.{self.zone.name}"

    def _create_record(self, record_value: str):
        response = self.client.post(
            reverse(
                modify_rrset,
                kwargs={"rr_name": self.rr_name},
            ),
            {
                "rr_type": "TXT",
                "rr_content": record_value,
                "edit_action": "add",
            },
        )
        self.assertEqual(response.status_code, 302)


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


class TestMockDomainNameHelper(WithUserTests):
    def test_mock(self):
        self.mock_domainNameHelper.return_value = str(uuid4())
        a = DomainNameHelper.objects.create()
        name = a.get_name()
        self.assertGreater(len(name), 10, f"{name}")

    def test_mock_api(self):
        self.client.force_login(self.testUser)
        a = self._create_free_domain()
        b = self._create_free_domain()
        self.assertTrue(len(a) < len(b) or a < b)
        self.assertTrue(a.endswith(".localhostcert.net."), a)
        self.assertTrue(b.endswith(".localhostcert.net."), b)


class TestListDomains(WithUserTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(list_zones)

    def test_list_zones(self):
        expected_name = str(uuid4())

        self.client.force_login(self.testUser)
        self._create_free_domain(expected_name)

        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create Free Domain")
        self.assertContains(response, "Manage", html=True)
        self.assertContains(response, f"{expected_name}.localhostcert.net.", html=True)

    def test_list_zones_empty(self):
        self.client.force_login(self.testUser)

        # No domains
        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create Free Domain")
        self.assertNotContains(response, "Manage", html=True)  # no domains to manage

    def test_limits(self):
        self.client.force_login(self.testUser)
        prefix = str(uuid4())

        for i in range(settings.LOCALCERT_DOMAIN_LIMIT):
            self._create_free_domain(f"{prefix}-{i}")

        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Create Free Domain")  # can't create more
        self.assertContains(response, "Manage", html=True)
        for i in range(settings.LOCALCERT_DOMAIN_LIMIT):
            self.assertContains(response, f"{prefix}-{i}.localhostcert.net")

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_get()

    def test_wrong_user(self):
        # testUser has one domain
        domain_name = "cantseeme"
        Zone.objects.create(
            name=domain_name,
            owner=self.testUser,
        )

        # but wrongUser can't see it
        self.client.force_login(self.wrongUser)
        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, domain_name)

    def test_wrong_method(self):
        self.assert_post_method_not_allowed()
        self.assert_head_method_not_allowed()


class TestCreateFreeDomains(WithUserTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(create_free_domain)

    def test_create_free_domain(self):
        self.client.force_login(self.testUser)

        self.mock_domainNameHelper.return_value = str(uuid4())
        response = self.client.post(self.target_url, follow=True)

        zone = Zone.objects.filter(owner=self.testUser)
        self.assertEqual(len(zone), 1, f"Found {len(zone)} zones, {response.content}")
        zone = zone[0]

        self.assertContains(response, zone.name, html=True)
        self.assertRedirects(
            response, reverse(describe_zone, kwargs={"zone_name": zone.name})
        )

    def test_limits(self):
        self.client.force_login(self.testUser)

        for i in range(settings.LOCALCERT_DOMAIN_LIMIT):
            Zone.objects.create(
                name=str(i),
                owner=self.testUser,
            )

        response = self.client.post(self.target_url)
        self.assertContains(
            response, "Domain limit already reached", status_code=400, html=True
        )

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        pass

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()
        self.assert_get_method_not_allowed()


class TestDescribeDomain(WithZoneTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(describe_zone, kwargs={"zone_name": self.zone.name})

    def test_describe_zone(self):
        self.client.force_login(self.testUser)
        response = self.client.get(self.target_url)
        self.assertContains(response, self.zone.name, html=True)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_get()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_get()

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()
        self.assert_post_method_not_allowed()


class TestListResourceRecord(WithZoneTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(
            describe_zone,
            kwargs={"zone_name": self.zone.name},
        )

    def test_list_single_record(self):
        self.client.force_login(self.testUser)

        record_value = randomDns01ChallengeResponse()
        self._create_record(record_value)

        response = self.client.get(self.target_url)
        self.assertContains(response, record_value)
        self.assertContains(response, "Add Record", html=True)

    def test_list_max_records(self):
        self.client.force_login(self.testUser)

        expectedValues = [
            randomDns01ChallengeResponse()
            for _ in range(settings.LOCALCERT_TXT_RECORDS_PER_RRSET_LIMIT)
        ]

        for v in expectedValues:
            self._create_record(v)

        response = self.client.get(self.target_url)
        for v in expectedValues:
            self.assertContains(response, v)
        self.assertNotContains(response, "Add Record", html=True)

    def test_can_only_delete_a_records(self):
        self.client.force_login(self.testUser)

        record_value = randomDns01ChallengeResponse()
        self._create_record(record_value)

        response = self.client.get(self.target_url)
        soup = bs(response.content.decode("utf-8"), "html.parser")
        txtRow = soup.find("tr", {"class": "TXT"})
        aRow = soup.find("tr", {"class": "A"})
        txtDeleteButton = txtRow.find("input", type="submit")
        aDeleteButton = aRow.find("input", type="submit")

        # TXT can be deleted
        self.assertHTMLEqual(str(txtDeleteButton), '<input type="submit" value="x">')

        response = self.client.post(
            reverse(
                modify_rrset,
                kwargs={"rr_name": self.rr_name},
            ),
            {
                "rr_type": "TXT",
                "rr_content": record_value,
                "edit_action": "remove",
            },
        )
        self.assertEqual(302, response.status_code)

        # A cannot (button is disabled)
        self.assertHTMLEqual(
            str(aDeleteButton),
            '<input type="submit" disabled title="Cannot delete" value="x">',
        )

        response = self.client.post(
            reverse(
                modify_rrset,
                kwargs={"rr_name": self.rr_name},
            ),
            {
                "rr_type": "A",
                "rr_content": "127.0.0.1",
                "edit_action": "remove",
            },
        )
        self.assertEqual(401, response.status_code)


class TestCreateResourceRecord(WithZoneTests):
    def setUp(self):
        super().setUp()
        self.create_page_url = reverse(
            create_resource_record_page,
            kwargs={"zone_name": self.zone.name},
        )
        self.target_url = reverse(
            modify_rrset,
            kwargs={"rr_name": self.rr_name},
        )
        self.record_value = randomDns01ChallengeResponse()
        self.request_body = {
            "rr_type": "TXT",
            "edit_action": "add",
            "rr_content": self.record_value,
        }

    def test_create_resource_record(self):
        self.client.force_login(self.testUser)

        response = self.client.get(self.create_page_url)
        self.assertContains(response, ACME_CHALLENGE_LABEL)
        self.assertContains(response, self.zone.name)

        response = self.client.post(
            self.target_url,
            self.request_body,
            follow=True,
        )
        expected_redirect = reverse(
            describe_zone,
            kwargs={
                "zone_name": self.zone.name,
            },
        )
        self.assertRedirects(response, expected_redirect)
        self.assertContains(response, ACME_CHALLENGE_LABEL)
        self.assertContains(response, self.record_value)

    def test_unsupported_domain(self):
        self.client.force_login(self.testUser)

        invalid_url = reverse(
            modify_rrset,
            kwargs={"rr_name": "foo.google.com"},
        )
        response = self.client.post(
            invalid_url,
            self.request_body,
            follow=True,
        )
        self.assertContains(response, "localhostcert.net", status_code=400)

    def test_rrname_too_long(self):
        self.client.force_login(self.testUser)

        long_rrname = ".localhostcert.net"
        extra = 253 - len(long_rrname) + 1
        if extra % 2 == 0:
            long_rrname = "aa." + long_rrname
            extra -= 3
        while extra > 2:
            long_rrname = "a." + long_rrname
            extra -= 2

        self._helper_invalid_rrname(long_rrname, "too long")

    def _helper_invalid_rrname(self, rrname, msg):
        invalid_url = reverse(
            modify_rrset,
            kwargs={"rr_name": rrname},
        )
        result = self.client.post(
            invalid_url,
            self.request_body,
            follow=True,
        )
        self.assertEqual(result.status_code, 400)
        self.assertIn(msg, result.content.decode("utf-8"))

    def test_invalid_rrnames(self):
        self.client.force_login(self.testUser)

        self._helper_invalid_rrname("A.localhostcert.net", "use lowercase")
        self._helper_invalid_rrname("..localhostcert.net", "label cannot be empty")
        self._helper_invalid_rrname("?.localhostcert.net", "invalid character")
        self._helper_invalid_rrname(
            TEN_CHARS * 6 + "1234" + ".localhostcert.net", "label too long"
        )
        self._helper_invalid_rrname(
            "-a.localhostcert.net", "label cannot start with hyphen"
        )
        self._helper_invalid_rrname(
            "a-.localhostcert.net", "label cannot end with hyphen"
        )
        self._helper_invalid_rrname(
            "a--a.localhostcert.net", "label cannot have multiple hyphens in a row"
        )

    def test_limits(self):
        self.client.force_login(self.testUser)

        for i in range(settings.LOCALCERT_TXT_RECORDS_PER_RRSET_LIMIT):
            self._create_record(randomDns01ChallengeResponse())

        response = self.client.post(self.target_url, self.request_body)
        self.assertContains(response, "Limit exceeded", status_code=400)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_post()

    def test_wrong_method(self):
        self.assert_get_method_not_allowed()
        self.assert_head_method_not_allowed()


class TestDeleteResourceRecord(WithZoneTests):
    def setUp(self):
        super().setUp()
        self.record_value = randomDns01ChallengeResponse()
        self._create_record(self.record_value)

        self.target_url = reverse(
            modify_rrset,
            kwargs={"rr_name": self.rr_name},
        )
        self.request_body = {
            "rr_type": "TXT",
            "rr_content": self.record_value,
            "edit_action": "remove",
        }

    def test_delete_resource_record(self):
        self.client.force_login(self.testUser)

        expected_redirect = reverse(
            describe_zone,
            kwargs={"zone_name": self.zone.name},
        )
        response = self.client.get(expected_redirect)
        self.assertContains(response, self.record_value)

        response = self.client.post(self.target_url, self.request_body, follow=True)
        self.assertRedirects(response, expected_redirect)
        self.assertContains(response, self.zone.name)
        self.assertNotContains(response, ACME_CHALLENGE_LABEL)
        self.assertNotContains(response, self.record_value)

    def test_cannot_modify_non_acme_record(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(
                modify_rrset,
                kwargs={"rr_name": f"wrong.{self.zone.name}"},
            ),
            {
                "rr_type": "TXT",
                "rr_content": randomDns01ChallengeResponse(),
                "edit_action": "add",
            },
        )
        self.assertContains(response, "Only _acme-challenge.", status_code=400)
        self.assertContains(response, " can be modified", status_code=400)

    def test_cannot_modify_subdomain_acme_record(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(
                modify_rrset,
                kwargs={"rr_name": f"{ACME_CHALLENGE_LABEL}.too-deep.{self.zone.name}"},
            ),
            {
                "rr_type": "TXT",
                "rr_content": randomDns01ChallengeResponse(),
                "edit_action": "add",
            },
        )
        self.assertContains(response, "Only _acme-challenge.", status_code=400)
        self.assertContains(response, " can be modified", status_code=400)

    def test_cannot_delete_non_existing(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(
                modify_rrset,
                kwargs={"rr_name": f"{ACME_CHALLENGE_LABEL}.{self.zone.name}"},
            ),
            {
                "rr_type": "TXT",
                "rr_content": randomDns01ChallengeResponse(),
                "edit_action": "remove",
            },
        )
        self.assertEqual(404, response.status_code)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_post()

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()
        self.assert_get_method_not_allowed()
