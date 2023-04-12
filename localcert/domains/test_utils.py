import json
import random

from .models import DomainNameHelper, Zone
from .pdns import pdns_create_zone
from .utils import CustomExceptionServerError
from .views import (
    acmedns_api_update,
    add_record,
    create_free_domain,
    create_zone_api_key,
)
from base64 import urlsafe_b64encode
from bs4 import BeautifulSoup as bs
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.test import TestCase
from django.urls import reverse
from hashlib import sha256
from typing import Tuple
from unittest.mock import patch
from uuid import uuid4


User = get_user_model()


def randomDns01ChallengeResponse() -> str:
    m = sha256()
    m.update(str(uuid4()).encode("utf-8"))
    return urlsafe_b64encode(m.digest()).decode("utf-8").replace("=", "")


def strip_trailing_dot(value: str) -> str:
    if value.endswith("."):
        value = value[0:-1]
    return value


class AlwaysSucceed(TestCase):
    def test_pass(self):
        pass


class WithMockDomainNameHelper(TestCase):
    def __init__(self, a):
        super().__init__(a)
        self.free_domain_index = random.randint(1_000, 1_000_000_000)

        try:
            pdns_create_zone("localhostcert.net.")
        except CustomExceptionServerError as e:
            if str(e) == "Conflict":
                pass
            else:
                raise e

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

        self.testUser = User.objects.create(username=str(uuid4()))
        self.wrongUser = User.objects.create(username=str(uuid4()))
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
        zones = Zone.objects.filter(owner=self.testUser)
        zones = [_ for _ in zones]
        assert len(zones) == 1, f"Found {len(zones)} zones."
        self.zone: Zone = zones[0]
        self.subdomain = self.zone.name.split(".")[0]

        badName = str(uuid4())
        self.mock_domainNameHelper.return_value = badName
        self.client.force_login(self.wrongUser)
        response = self.client.post(
            reverse(create_free_domain),
            follow=True,
        )
        self.assertContains(response, badName)
        zones = Zone.objects.filter(owner=self.wrongUser)
        zones = [_ for _ in zones]
        assert len(zones) == 1, f"Found {len(zones)} zones."
        self.wrongUserZone: Zone = zones[0]

    def _create_record(self, record_value: str):
        self.client.force_login(self.testUser)
        response = self.client.post(
            reverse(
                add_record,
            ),
            {
                "zone_name": self.zone.name,
                "rr_content": record_value,
            },
        )
        self.assertEqual(response.status_code, 302)

    def _create_api_key(self, zone_name=None) -> HttpResponse:
        if zone_name is None:
            zone_name = self.zone.name
        return self.client.post(
            reverse(
                create_zone_api_key,
            ),
            {"zone_name": zone_name},
        )

    def _parse_api_key_response(self, response: HttpResponse) -> Tuple[str, str]:
        soup = bs(response.content.decode("utf-8"), "html.parser")
        secretKeyID = soup.find(id="secretKeyId").text.strip()
        secretKey = soup.find(id="secretKey").text.strip()
        return secretKeyID, secretKey


class WithApiKey(WithZoneTests):
    def setUp(self):
        super().setUp()
        self.client.force_login(self.testUser)
        response = self._create_api_key()
        self.secretKeyId, self.secretKey = self._parse_api_key_response(response)

        self.client.force_login(self.wrongUser)
        response = self._create_api_key(self.wrongUserZone)
        (
            self.wrongUserSecretKeyId,
            self.wrongUserSecretKey,
        ) = self._parse_api_key_response(response)

    def _make_challenge(self):
        challenge = str(uuid4())
        challenge_hash_bytes = sha256(challenge.encode("utf-8")).digest()
        return urlsafe_b64encode(challenge_hash_bytes).decode("utf-8").replace("=", "")

    def _acmedns_update(self, challenge_b64: str) -> HttpResponse:
        return self.client.post(
            reverse(acmedns_api_update),
            json.dumps(
                {
                    "subdomain": self.subdomain,
                    "txt": challenge_b64,
                }
            ),
            content_type="application/json",
            HTTP_HOST="api.getlocalcert.net",
            HTTP_X_API_USER=self.secretKeyId,
            HTTP_X_API_KEY=self.secretKey,
        )


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
