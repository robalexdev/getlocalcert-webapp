import dns

from .test_utils import WithApiKey
from .views import (
    acmedns_api_extra_check,
    acmedns_api_health,
    acmedns_api_update,
    describe_zone,
)
from django.conf import settings
from django.urls import reverse
from domains.constants import ACME_CHALLENGE_LABEL, TXT_RECORDS_PER_RRSET_LIMIT
from uuid import uuid4


class TestExtraApi(WithApiKey):
    def test_extra_check(self):
        response = self.client.get(
            reverse(acmedns_api_extra_check),
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertEqual(200, response.status_code)
        response = response.json()
        self.assertEqual(response["status"], "ok")
        self.assertEqual(response["domain"], self.zone.name)

    def test_extra_check_bad_user_id(self):
        response = self.client.get(
            reverse(acmedns_api_extra_check),
            HTTP_X_API_USER=uuid4(),
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertEqual(401, response.status_code)

    def test_extra_check_bad_secret(self):
        response = self.client.get(
            reverse(acmedns_api_extra_check),
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey + "xxx",
        )
        self.assertEqual(401, response.status_code)

    def test_missing_api_key(self):
        response = self.client.get(
            reverse(acmedns_api_extra_check),
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertContains(
            response, "Missing required header X-Api-User", status_code=400
        )

        response = self.client.get(
            reverse(acmedns_api_extra_check),
            HTTP_X_API_USER=self.secretKeyId,
        )
        self.assertContains(
            response, "Missing required header X-Api-Key", status_code=400
        )


class TestAcmeApi(WithApiKey):
    def test_health(self):
        response = self.client.get(reverse(acmedns_api_health))
        self.assertEqual(200, response.status_code)
        self.assertEqual("{}", response.content.decode("utf-8"))

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
        values = []
        # add records until overflow occurs
        for _ in range(TXT_RECORDS_PER_RRSET_LIMIT + 1):
            challenge_b64 = self._make_challenge()
            response = self._acmedns_update(challenge_b64)
            self.assertTrue(200, response.status_code)
            values.append(challenge_b64)

        # Also check that we can see the record in the UI
        self.client.force_login(self.testUser)
        response = self.client.get(
            reverse(
                describe_zone,
            ),
            {"zone_name": self.zone.name},
        )

        # Only the two newest should exist
        self.assertContains(response, values[-1])

        # TODO: This is broken!
        # self.assertContains(response, values[-2])
        # but not the oldest
        # self.assertNotContains(response, values[0])

    def test_update_cannot_change_subdomains(self):
        challenge_b64 = self._make_challenge()
        response = self.client.post(
            reverse(acmedns_api_update),
            {
                "subdomain": "foo." + self.subdomain,
                "txt": challenge_b64,
            },
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertContains(response, "Subdomain does not exist", status_code=404)

    def test_update_cannot_change_unrelated_domain(self):
        challenge_b64 = self._make_challenge()
        response = self.client.post(
            reverse(acmedns_api_update),
            {
                "subdomain": str(uuid4()),
                "txt": challenge_b64,
            },
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertContains(response, "Subdomain does not exist", status_code=404)

    def test_missing_inputs(self):
        challenge_b64 = self._make_challenge()
        response = self.client.post(
            reverse(acmedns_api_update),
            {
                "txt": challenge_b64,
            },
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertContains(
            response, "subdomain: This field is required", status_code=400
        )

        response = self.client.post(
            reverse(acmedns_api_update),
            {
                "subdomain": str(uuid4()),
            },
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertContains(response, "txt: This field is required", status_code=400)
