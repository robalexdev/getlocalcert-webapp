import dns
import json

from .test_utils import WithApiKey
from .views import (
    acmedns_api_health,
    acmedns_api_register,
    acmedns_api_update,
    api_check_key,
    api_health,
    describe_zone,
)
from django.conf import settings
from django.urls import reverse
from domains.constants import ACME_CHALLENGE_LABEL, TXT_RECORDS_PER_RRSET_LIMIT
from uuid import uuid4


class TestExtraApi(WithApiKey):
    def test_health(self):
        response = self.client.get(reverse(api_health))
        self.assertEqual(200, response.status_code)
        self.assertEqual('{"healthy": true}', response.content.decode("utf-8"))

    def test_extra_check(self):
        response = self.client.get(
            reverse(api_check_key),
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertEqual(200, response.status_code)
        response = response.json()
        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["domain"], self.zone.name)

    def test_extra_check_bad_user_id(self):
        response = self.client.get(
            reverse(api_check_key),
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=uuid4(),
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertEqual(401, response.status_code)

    def test_extra_check_bad_secret(self):
        response = self.client.get(
            reverse(api_check_key),
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey + "xxx",
        )
        self.assertEqual(401, response.status_code)

    def test_missing_api_key(self):
        response = self.client.get(
            reverse(api_check_key),
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertContains(
            response, "Missing required header X-Api-User", status_code=400
        )

        response = self.client.get(
            reverse(api_check_key),
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=self.secretKeyId,
        )
        self.assertContains(
            response, "Missing required header X-Api-Key", status_code=400
        )


class TestAcmeApi(WithApiKey):
    def test_health(self):
        response = self.client.get(
            reverse(acmedns_api_health),
            HTTP_HOST="api.getlocalcert.net",
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual("", response.content.decode("utf-8"))

    def test_can_register_zone(self):
        response = self.client.post(
            reverse(acmedns_api_register),
            HTTP_HOST="api.getlocalcert.net",
        )
        self.assertEqual(201, response.status_code)
        response = response.json()
        username = response["username"]
        password = response["password"]
        subdomain = response["subdomain"]
        fulldomain = response["fulldomain"]
        allowfrom = response["allowfrom"]

        self.assertEqual(len(username), len(str(uuid4())))
        self.assertGreaterEqual(len(password), 32)
        self.assertTrue(fulldomain.startswith(subdomain))
        self.assertEqual(allowfrom, [])

    def test_update_anonymous_zone(self):
        response = self.client.post(
            reverse(acmedns_api_register),
            HTTP_HOST="api.getlocalcert.net",
        )
        response = response.json()
        username = response["username"]
        password = response["password"]
        subdomain = response["subdomain"]
        challenge = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        response = self.client.post(
            reverse(acmedns_api_update),
            json.dumps(
                {
                    "subdomain": subdomain,
                    "txt": challenge,
                }
            ),
            content_type="application/json",
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=username,
            HTTP_X_API_KEY=password,
        )

    def test_update_txt_record(self):
        challenge_b64 = self._make_challenge()
        response = self._acmedns_update(challenge_b64)
        self.assertTrue(200, response.status_code)
        response = response.json()
        self.assertEqual(response["txt"], challenge_b64)

        # Also check that we can see the record in the UI
        self.client.force_login(self.testUser)
        response = self.client.get(
            reverse(
                describe_zone,
            ),
            {"zone_name": self.zone.name},
        )
        self.assertContains(response, challenge_b64)

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
            any([challenge_b64 in str(answer) for answer in dns_resp.answer])
        )

    def test_update_txt_records_drops_oldest(self):
        assert TXT_RECORDS_PER_RRSET_LIMIT == 2, "Update this code"
        challenge_one = "a" * 43
        challenge_two = "b" * 43
        challenge_three = "c" * 43

        self.client.force_login(self.testUser)

        # Add first record
        response = self._acmedns_update(challenge_one)
        self.assertContains(response, challenge_one)

        # Make sure first record is present
        response = self.client.get(
            reverse(describe_zone),
            {"zone_name": self.zone.name},
        )
        self.assertContains(response, challenge_one)

        # Add second record
        response = self._acmedns_update(challenge_two)
        self.assertContains(response, challenge_two)

        # Make sure both records are present
        response = self.client.get(
            reverse(describe_zone),
            {"zone_name": self.zone.name},
        )
        self.assertContains(response, challenge_one)
        self.assertContains(response, challenge_two)

        # Add third record, trigger overlow
        response = self._acmedns_update(challenge_three)
        self.assertContains(response, challenge_three)

        # Make sure oldest record is gone, other two are present
        response = self.client.get(
            reverse(describe_zone),
            {"zone_name": self.zone.name},
        )
        self.assertNotContains(response, challenge_one)
        self.assertContains(response, challenge_two)
        self.assertContains(response, challenge_three)

    def test_update_requires_api_hostname(self):
        response = self.client.post(
            reverse(acmedns_api_update),
            json.dumps(
                {}
            ),  # <- empty body, no auth. ensure hostname error is checked first
            content_type="application/json",
            HTTP_HOST="console.getlocalcert.net",  # <- wrong hostname
        )
        self.assertContains(response, "Not Found", status_code=404)

    def test_update_cannot_change_subdomains(self):
        challenge_b64 = self._make_challenge()
        response = self.client.post(
            reverse(acmedns_api_update),
            json.dumps(
                {
                    "subdomain": "foo-" + self.subdomain,
                    "txt": challenge_b64,
                }
            ),
            content_type="application/json",
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertContains(response, "Subdomain does not exist", status_code=404)

    def test_update_cannot_change_unrelated_domain(self):
        challenge_b64 = self._make_challenge()
        response = self.client.post(
            reverse(acmedns_api_update),
            json.dumps(
                {
                    "subdomain": str(uuid4()),
                    "txt": challenge_b64,
                }
            ),
            content_type="application/json",
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertContains(response, "Subdomain does not exist", status_code=404)

    def test_missing_inputs(self):
        challenge_b64 = self._make_challenge()
        response = self.client.post(
            reverse(acmedns_api_update),
            json.dumps(
                {
                    "txt": challenge_b64,
                }
            ),
            content_type="application/json",
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertContains(
            response, "subdomain: This field is required", status_code=400
        )

        response = self.client.post(
            reverse(acmedns_api_update),
            json.dumps(
                {
                    "subdomain": str(uuid4()),
                }
            ),
            content_type="application/json",
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertContains(response, "txt: This field is required", status_code=400)
