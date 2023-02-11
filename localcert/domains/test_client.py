import dns.message
import dns.query

from .constants import (
    ACME_CHALLENGE_LABEL,
    API_KEY_PER_ZONE_LIMIT,
    DOMAIN_PER_USER_LIMIT,
    TXT_RECORDS_PER_RRSET_LIMIT,
)
from .models import (
    Zone,
)
from .test_utils import (
    WithUserTests,
    WithZoneTests,
    randomDns01ChallengeResponse,
    strip_trailing_dot,
)
from .utils import (
    build_url,
)
from .views import (
    add_record,
    create_free_domain,
    create_zone_api_key,
    delete_record,
    delete_zone_api_key,
    describe_zone,
    list_zones,
)
from django.conf import settings
from django.urls import reverse
from uuid import uuid4


TEN_CHARS = "1234567890"


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
        self.assertContains(response, f"{expected_name}.localhostcert.net", html=True)

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

        for i in range(DOMAIN_PER_USER_LIMIT):
            self._create_free_domain(f"{prefix}-{i}")

        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Create Free Domain")  # can't create more
        self.assertContains(response, "Manage", html=True)
        for i in range(DOMAIN_PER_USER_LIMIT):
            self.assertContains(response, f"{prefix}-{i}.localhostcert.net")

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_get()

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

        self.assertContains(response, strip_trailing_dot(zone.name), html=True)
        self.assertRedirects(
            response, build_url(describe_zone, params={"zone_name": zone.name})
        )

    def test_limits(self):
        self.client.force_login(self.testUser)

        for i in range(DOMAIN_PER_USER_LIMIT):
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
        self.assertContains(response, "<domain>.localhostcert.net", status_code=400)

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
        dns_req = dns.message.make_query(
            f"{ACME_CHALLENGE_LABEL}.{self.zone.name}", "TXT"
        )
        dns_resp = dns.query.udp(
            dns_req,
            where=settings.LOCALCERT_PDNS_SERVER_IP,
            port=settings.LOCALCERT_PDNS_DNS_PORT,
        )
        self.assertTrue(
            any([self.record_value in str(answer) for answer in dns_resp.answer])
        )

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
        # TODO: check message "was added"
        self.assertContains(response, self.record_value)
        response = self.client.post(
            self.target_url,
            self.request_body,
            follow=True,
        )
        # TODO: check message "already exists"
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

        self._helper_invalid_rrname("A.localhostcert.net", "Use lowercase")
        self._helper_invalid_rrname(".localhostcert.net", "label cannot be empty")
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
            "&lt;domain&gt;.localhostcert.net",
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
        )
        self.assertEqual(404, response.status_code)

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
        self.assertContains(response, "<domain>.localhostcert.net", status_code=400)

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
        )
        self.assertRedirects(
            response,
            build_url(
                describe_zone,
                params={"zone_name": self.zone.name},
            ),
            status_code=302,
        )

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
