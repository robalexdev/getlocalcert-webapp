import json

from .test_utils import WithApiKey
from .views import (
    acmedns_api_update,
    add_record,
    create_zone_api_key,
    delete_record,
    delete_zone_api_key,
    describe_zone,
    list_zones,
)
from django.urls import reverse


class PermissionsTests(WithApiKey):
    """
    Every API should have a dedicated test here
    Verify that user access doesn't permit cross account access
    """

    def setUp(self) -> None:
        super().setUp()

    def test_attacker_cant_see_other_domains(self):
        self.client.force_login(self.testUser)
        response = self.client.get(reverse(list_zones))
        self.assertContains(response, self.zone.name)

        self.client.force_login(self.wrongUser)
        response = self.client.get(reverse(list_zones))
        self.assertNotContains(response, self.zone.name)

    def test_attacker_cant_describe_user_domains(self):
        self.client.force_login(self.testUser)
        response = self.client.get(
            reverse(describe_zone),
            {"zone_name": self.zone.name},
        )
        self.assertContains(response, self.zone.name)

        self.client.force_login(self.wrongUser)
        response = self.client.get(
            reverse(describe_zone),
            {"zone_name": self.zone.name},
        )
        self.assertNotContains(response, self.zone.name, status_code=404)
        self.assertContains(response, "Domain does not exist", status_code=404)

    def test_attacker_cant_create_keys_for_user_domains(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(create_zone_api_key),
            {"zone_name": self.zone.name},
        )
        self.assertContains(response, "API Key Created")

        self.client.force_login(self.wrongUser)
        response = self.client.post(
            reverse(create_zone_api_key),
            {"zone_name": self.zone.name},
        )
        self.assertNotContains(response, "API Key Created", status_code=404)
        self.assertContains(response, "Domain does not exist", status_code=404)

    def test_attacker_cant_delete_keys_for_user_domains(self):
        self.client.force_login(self.wrongUser)
        response = self.client.post(
            reverse(delete_zone_api_key),
            {"secret_key_id": self.secretKeyId},
            follow=True,
        )
        self.assertNotContains(response, "Deleted API key", status_code=404)
        self.assertContains(response, "API Key does not exist", status_code=404)

        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(delete_zone_api_key),
            {"secret_key_id": self.secretKeyId},
            follow=True,
        )

        # TODO message here
        # self.assertContains(response, "Deleted API key")
        self.assertNotContains(response, "API Key does not exist")

    def test_that_stolen_keys_can_be_deleted(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(delete_zone_api_key),
            {"secret_key_id": self.secretKeyId},
            follow=True,
        )
        # TODO: messaging needed
        # self.assertContains(response, "Deleted API key")

        # attacker can no longer use stolen key
        response = self.client.post(
            reverse(acmedns_api_update),
            json.dumps(
                {
                    "subdomain": self.subdomain,
                    "txt": self._make_challenge(),
                }
            ),
            content_type="application/json",
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertContains(response, "Unauthorized", status_code=401)

    def test_attacker_cant_update_records_for_user_domains(self):
        badChallenge = self._make_challenge()
        response = self.client.post(
            reverse(acmedns_api_update),
            json.dumps(
                {
                    "subdomain": self.subdomain,
                    "txt": badChallenge,
                }
            ),
            content_type="application/json",
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=self.wrongUserSecretKeyId,
            HTTP_X_API_KEY=self.wrongUserSecretKey,
        )
        self.assertContains(response, "Subdomain does not exist", status_code=404)

        goodChallenge = self._make_challenge()
        response = self.client.post(
            reverse(acmedns_api_update),
            json.dumps(
                {
                    "subdomain": self.subdomain,
                    "txt": goodChallenge,
                }
            ),
            content_type="application/json",
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )
        self.assertContains(response, goodChallenge)
        self.assertNotContains(response, "Subdomain does not exist")
        self.assertNotContains(response, badChallenge)

    def test_attacker_cannot_delete_records_for_user(self):
        self.client.force_login(self.testUser)
        goodRecord = self._make_challenge()
        self._create_record(goodRecord)

        self.client.force_login(self.wrongUser)
        response = self.client.post(
            reverse(delete_record),
            {
                "zone_name": self.zone.name,
                "rr_content": goodRecord,
            },
            follow=True,
        )
        self.assertContains(response, "Domain does not exist", status_code=404)

        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(delete_record),
            {
                "zone_name": self.zone.name,
                "rr_content": goodRecord,
            },
            follow=True,
        )
        self.assertNotContains(response, "Domain does not exist")

    def test_attacker_cannot_add_records_for_user(self):
        badRecord = self._make_challenge()
        self.client.force_login(self.wrongUser)
        response = self.client.post(
            reverse(add_record),
            {
                "zone_name": self.zone.name,
                "rr_content": badRecord,
            },
            follow=True,
        )
        self.assertNotContains(response, "Record added", status_code=404)
        self.assertContains(response, "Domain does not exist", status_code=404)

        goodRecord = self._make_challenge()
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(add_record),
            {
                "zone_name": self.zone.name,
                "rr_content": goodRecord,
            },
            follow=True,
        )
        self.assertNotContains(response, "Domain does not exist")

        # TODO: messaging
        # self.assertContains(response, "Record added")
