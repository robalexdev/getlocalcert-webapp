import dns.message
import dns.query

from .constants import (
    ACME_CHALLENGE_LABEL,
    API_KEY_PER_ZONE_LIMIT,
    DOMAIN_PER_STAFF_LIMIT,
    DOMAIN_PER_USER_LIMIT,
    TXT_RECORDS_PER_RRSET_LIMIT,
)
from .models import (
    Zone,
)
from .test_utils import (
    WithApiKey,
    WithUserTests,
    WithZoneTests,
    randomDns01ChallengeResponse,
    strip_trailing_dot,
)
from .utils import (
    build_url,
    domain_limit_for_user,
)
from .views import (
    add_record,
    register_subdomain,
    create_zone_api_key,
    delete_record,
    delete_zone_api_key,
    describe_zone,
    list_zones,
    show_stats,
)
from django.conf import settings
from django.urls import reverse
from uuid import uuid4


TEN_CHARS = "1234567890"


def simple_dns_query(rr_name: str, record_type: str):
    dns_req = dns.message.make_query(
        rr_name,
        record_type,
    )
    dns_resp = dns.query.udp(
        dns_req,
        where=settings.LOCALCERT_PDNS_SERVER_IP,
        port=settings.LOCALCERT_PDNS_DNS_PORT,
    )

    # Split
    answers = [str(answer).split("\n") for answer in dns_resp.answer]
    # Flatten
    answers = [item for inner in answers for item in inner]
    # The answer has a couple parts, get the end
    return [str(answer).split(f" IN {record_type} ")[1] for answer in answers]


class TestListDomains(WithUserTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(list_zones)

    def test_list_zones(self):
        expected_name = str(uuid4())

        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse("register_subdomain"),
            {
                "subdomain": expected_name,
                "parent_zone": "localcert.net.",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)

        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Register a free subdomain")
        self.assertContains(response, "Manage", html=True)
        self.assertContains(response, f"{expected_name}.localcert.net", html=True)

    def test_list_zones_empty(self):
        self.client.force_login(self.testUser)

        # No domains
        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Register a free subdomain")
        self.assertNotContains(response, "Manage", html=True)  # no domains to manage

    def test_limits(self):
        self.client.force_login(self.testUser)
        prefix = str(uuid4())

        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response, "Register a free subdomain"
        )  # initially, can create

        for i in range(DOMAIN_PER_USER_LIMIT):
            response = self.client.post(
                reverse("register_subdomain"),
                {
                    "subdomain": f"{prefix}-{i}",
                    "parent_zone": "localcert.net.",
                },
                follow=True,
            )
            self.assertEqual(response.status_code, 200)

        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(
            response, "Register a free subdomain"
        )  # can't create more
        self.assertContains(response, "Manage", html=True)
        for i in range(DOMAIN_PER_USER_LIMIT):
            self.assertContains(response, f"{prefix}-{i}.localcert.net")

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_get()

    def test_wrong_method(self):
        self.assert_post_method_not_allowed()
        self.assert_head_method_not_allowed()


class TestCreateFreeDomains(WithUserTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(register_subdomain)

    def test_get_register_form(self):
        self.client.force_login(self.testUser)

        response = self.client.get(self.target_url)
        self.assertContains(response, "Register Subdomain", html=True)
        self.assertContains(response, "localhostcert.net", html=True)
        self.assertContains(response, "localcert.net", html=True)
        # Add later
        self.assertNotContains(response, "corpnet.work", html=True)

    def test_register_subdomain(self):
        self.client.force_login(self.testUser)

        subdomain = str(uuid4())
        response = self.client.post(
            self.target_url,
            {
                "subdomain": subdomain,
                "parent_zone": "localhostcert.net.",
            },
            follow=True,
        )

        zone = Zone.objects.filter(owner=self.testUser)
        self.assertEqual(len(zone), 1, f"Found {len(zone)} zones, {response.content}")
        zone = zone[0]

        self.assertContains(response, strip_trailing_dot(zone.name), html=True)
        self.assertContains(response, f"Created {zone.name}")
        self.assertRedirects(
            response, build_url(describe_zone, params={"zone_name": zone.name})
        )

    def test_invalid_subdomain(self):
        self.client.force_login(self.testUser)

        invalid_names = {
            "": "This field is required",
            "-a": "cannot start with hyphen",
            "a-": "cannot end with hyphen",
            "a--a": "multiple hyphens",
            "a.b": "cannot contain a &#x27;.&#x27;",
            "1234567890123456789012345678901234567890123456789012345678901234567890": "too long",
        }

        for invalid_name, expected_error in invalid_names.items():
            response = self.client.post(
                self.target_url,
                {
                    "subdomain": invalid_name,
                    "parent_zone": "localhostcert.net.",
                },
                follow=True,
            )
            self.assertContains(response, expected_error, status_code=400)

    def test_banned_subdomain(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            self.target_url,
            {
                "subdomain": "mil",
                "parent_zone": "localhostcert.net.",
            },
            follow=True,
        )
        self.assertContains(response, "on a blocklist", status_code=400)

    def test_already_registered(self):
        subdomain = str(uuid4())

        # First, let someone else register the subdomain
        self.client.force_login(self.wrongUser)
        response = self.client.post(
            self.target_url,
            {
                "subdomain": subdomain,
                "parent_zone": "localhostcert.net.",
            },
            follow=True,
        )
        self.assertEqual(200, response.status_code)

        # Try to register the existing subdomain as the same user
        response = self.client.post(
            self.target_url,
            {
                "subdomain": subdomain,
                "parent_zone": "localhostcert.net.",
            },
            follow=True,
        )
        self.assertContains(response, "Subdomain already registered", status_code=400)

        # Try to register the existing subdomain as a different user
        self.client.force_login(self.testUser)
        response = self.client.post(
            self.target_url,
            {
                "subdomain": subdomain,
                "parent_zone": "localhostcert.net.",
            },
            follow=True,
        )
        self.assertContains(response, "Subdomain already registered", status_code=400)

    def test_limits(self):
        self.client.force_login(self.testUser)

        for i in range(DOMAIN_PER_USER_LIMIT):
            Zone.objects.create(
                name=str(i),
                owner=self.testUser,
            )

        subdomain = str(uuid4())
        response = self.client.post(
            self.target_url,
            {
                "subdomain": subdomain,
                "parent_zone": "localhostcert.net.",
            },
            follow=True,
        )
        self.assertContains(
            response, "Subdomain limit already reached", status_code=400, html=True
        )

    def test_register_subdomain_dns_entries(self):
        self.client.force_login(self.testUser)

        subdomain = str(uuid4())
        response = self.client.post(
            self.target_url,
            {
                "subdomain": subdomain,
                "parent_zone": "localhostcert.net.",
            },
            follow=True,
        )

        zone = Zone.objects.filter(owner=self.testUser)
        self.assertEqual(len(zone), 1, f"Found {len(zone)} zones, {response.content}")
        zone = zone[0]

        # Also check that we can see the record in DNS
        answers = simple_dns_query(zone.name, "A")
        self.assertTrue("127.0.0.1" in answers)

        answers = simple_dns_query(zone.name, "NS")
        self.assertTrue("ns1.example.com." in answers)
        self.assertTrue("ns2.example.com." in answers)

        answers = simple_dns_query(zone.name, "SOA")
        self.assertTrue(any(["ns1.example.com. " in answer for answer in answers]))

        # Can't send/recv email
        answers = simple_dns_query(zone.name, "MX")
        self.assertTrue("0 ." in answers)

        answers = simple_dns_query(f"*._domainkey.{zone.name}", "TXT")
        self.assertTrue('"v=DKIM1; p="' in answers)

        answers = simple_dns_query(zone.name, "TXT")
        self.assertTrue('"v=spf1 -all"' in answers)

        answers = simple_dns_query(f"_dmarc.{zone.name}", "TXT")
        self.assertTrue('"v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"' in answers)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        pass

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()


class TestDescribeDomain(WithZoneTests):
    def setUp(self):
        super().setUp()
        self.target_url = build_url(describe_zone, params={"zone_name": self.zone.name})

    def test_describe_zone(self):
        self.client.force_login(self.testUser)
        response = self.client.get(self.target_url)
        self.assertContains(response, strip_trailing_dot(self.zone.name), html=True)

    def test_describe_invalid_zone_names(self):
        self.client.force_login(self.testUser)
        target_url = build_url(describe_zone, params={"zone_name": "a" * 256})
        response = self.client.get(target_url)
        self.assertEqual(400, response.status_code)

        target_url = build_url(describe_zone, params={"zone_name": ""})
        response = self.client.get(target_url)
        self.assertContains(response, "This field is required", status_code=400)

        target_url = build_url(
            describe_zone, params={"zone_name": "a.b.localhostcert.net."}
        )
        response = self.client.get(target_url)
        self.assertContains(response, "<subdomain>.localhostcert.net", status_code=400)

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
        self.target_url = build_url(
            describe_zone,
            params={"zone_name": self.zone.name},
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
            randomDns01ChallengeResponse() for _ in range(TXT_RECORDS_PER_RRSET_LIMIT)
        ]

        for v in expectedValues:
            self._create_record(v)

        response = self.client.get(self.target_url)
        for v in expectedValues:
            self.assertContains(response, v)
        self.assertNotContains(response, "Add Record", html=True)


class TestCreateResourceRecord(WithZoneTests):
    def setUp(self):
        super().setUp()
        self.create_page_url = build_url(
            add_record,
            params={"zone_name": self.zone.name},
        )
        self.target_url = reverse(add_record)
        self.record_value = randomDns01ChallengeResponse()
        self.request_body = {
            "zone_name": self.zone.name,
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
        expected_redirect = build_url(
            describe_zone,
            params={
                "zone_name": self.zone.name,
            },
        )
        self.assertRedirects(response, expected_redirect)
        self.assertContains(response, ACME_CHALLENGE_LABEL)
        self.assertContains(response, self.record_value)

        # Also check that we can see the record in DNS
        answers = simple_dns_query(
            f"{ACME_CHALLENGE_LABEL}.{self.zone.name}",
            "TXT",
        )
        self.assertTrue(f'"{self.record_value}"' in answers)

    def test_unsupported_domain(self):
        self.client.force_login(self.testUser)
        body = self.request_body.copy()
        body["zone_name"] = "foo.google.com"
        response = self.client.post(
            self.target_url,
            body,
            follow=True,
        )
        self.assertContains(response, "localhostcert.net", status_code=400)

    def test_add_record_twice(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            self.target_url,
            self.request_body,
            follow=True,
        )
        self.assertContains(response, "Record added")
        self.assertContains(response, self.record_value)
        response = self.client.post(
            self.target_url,
            self.request_body,
            follow=True,
        )
        self.assertContains(response, "Record already exists")
        self.assertContains(response, self.record_value)

    def _helper_invalid_rrname(self, rrname, msg):
        body = self.request_body
        body["zone_name"] = rrname

        result = self.client.post(
            self.target_url,
            body,
            follow=True,
        )
        self.assertEqual(result.status_code, 400)
        self.assertIn(msg, result.content.decode("utf-8"))

    def test_invalid_rrnames(self):
        self.client.force_login(self.testUser)

        self._helper_invalid_rrname("A.localhostcert.net", "use lowercase")
        self._helper_invalid_rrname(".localhostcert.net", "label cannot be empty")
        self._helper_invalid_rrname("?.localhostcert.net", "invalid character")
        self._helper_invalid_rrname(
            TEN_CHARS * 6 + "1234" + ".localhostcert.net", "label is too long"
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

        for i in range(TXT_RECORDS_PER_RRSET_LIMIT):
            self._create_record(randomDns01ChallengeResponse())

        response = self.client.post(self.target_url, self.request_body)
        self.assertContains(response, "Limit exceeded", status_code=400)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_post()

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()


class TestDeleteResourceRecord(WithZoneTests):
    def setUp(self):
        super().setUp()
        self.record_value = randomDns01ChallengeResponse()
        self._create_record(self.record_value)

        self.target_url = reverse(delete_record)
        self.request_body = {
            "zone_name": self.zone.name,
            "rr_content": self.record_value,
        }

    def test_delete_resource_record(self):
        self.client.force_login(self.testUser)

        expected_redirect = build_url(
            describe_zone,
            params={
                "zone_name": self.zone.name,
            },
        )
        response = self.client.get(
            self.target_url,
            {
                "zone_name": self.zone.name,
                "rr_content": self.record_value,
            },
        )
        self.assertContains(response, self.record_value)

        response = self.client.post(self.target_url, self.request_body, follow=True)
        self.assertRedirects(response, expected_redirect)
        self.assertContains(response, "Record removed")
        self.assertContains(response, self.zone.name)
        self.assertNotContains(response, ACME_CHALLENGE_LABEL)
        self.assertNotContains(response, self.record_value)

    def test_delete_resource_record_invalid_input(self):
        response = self.client.post(
            self.target_url,
            {
                "zone_name": self.zone.name,
                "rr_content": "not an acme challenge",
            },
        )
        self.assertContains(
            response, "challenge response must be base64url encoded", status_code=400
        )

    def test_cannot_modify_subdomain_acme_record(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(
                add_record,
            ),
            {
                "zone_name": f"too-deep.{self.zone.name}",
                "rr_content": randomDns01ChallengeResponse(),
            },
        )
        self.assertContains(
            response,
            "&lt;subdomain&gt;.localhostcert.net",
            status_code=400,
        )

    def test_cannot_delete_non_existing(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(
                delete_record,
            ),
            {
                "zone_name": self.zone.name,
                "rr_content": randomDns01ChallengeResponse(),
            },
            follow=True,
        )
        self.assertContains(response, "Nothing was removed")

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_post()

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()


class TestZoneApiKey(WithZoneTests):
    def test_create_key(self):
        self.client.force_login(self.testUser)
        response = self._create_api_key()
        self.assertEqual(200, response.status_code)

        secretKeyId, secretKey = self._parse_api_key_response(response)
        self.assertTrue(len(secretKeyId) > 10)
        self.assertTrue(len(secretKey) > 10)

    def test_create_key_limit(self):
        self.client.force_login(self.testUser)

        for i in range(API_KEY_PER_ZONE_LIMIT):
            response = self._create_api_key()
            self.assertEqual(200, response.status_code)

        response = self._create_api_key()
        self.assertContains(response, "Cannot create more", status_code=400)

    def test_can_create_domain_api_key(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(
                create_zone_api_key,
            ),
            {"zone_name": self.zone.name},
        )
        self.assertContains(response, "API Key Created")

    def test_cannot_create_subdomain_api_key(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(
                create_zone_api_key,
            ),
            {"zone_name": "subdomain." + self.zone.name},
        )
        self.assertNotContains(response, "API Key Created", status_code=400)
        self.assertContains(
            response,
            "Domain name should use the form <subdomain>.localhostcert.net",
            status_code=400,
        )

    def test_cannot_create_blank_subdomain_api_key(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(
                create_zone_api_key,
            ),
            {"zone_name": ""},
        )
        self.assertNotContains(response, "API Key Created", status_code=400)
        self.assertContains(
            response,
            "required",
            status_code=400,
        )

    def test_delete_key(self):
        # Create a key
        self.client.force_login(self.testUser)
        response = self._create_api_key()
        secretKeyId, _ = self._parse_api_key_response(response)

        # Delete key
        response = self.client.post(
            reverse(
                delete_zone_api_key,
            ),
            {
                "zone_name": self.zone.name,
                "secret_key_id": secretKeyId,
            },
            follow=True,
        )
        expected_redirect = build_url(
            describe_zone,
            params={"zone_name": self.zone.name},
        )
        self.assertEqual(expected_redirect, response.redirect_chain[0][0])
        self.assertContains(response, "API Key deleted")

    def test_delete_key_invalid_input(self):
        # Delete key
        response = self.client.post(
            reverse(
                delete_zone_api_key,
            ),
            {
                "zone_name": self.zone.name,
                "secret_key_id": "not a uuid",
            },
        )
        self.assertContains(
            response, "secret_key_id: Enter a valid value", status_code=400
        )


class DomainLimitTests(WithUserTests):
    def setUp(self):
        super().setUp()

    def test_normal_user_limit(self):
        self.assertEqual(DOMAIN_PER_USER_LIMIT, domain_limit_for_user(self.testUser))
        self.assertEqual(DOMAIN_PER_STAFF_LIMIT, domain_limit_for_user(self.staffUser))


class StatsTests(WithApiKey):
    def setUp(self):
        super().setUp()

    def test_can_show_stats(self):
        response = self.client.get(reverse(show_stats))
        self.assertContains(response, "Users", html=True)
