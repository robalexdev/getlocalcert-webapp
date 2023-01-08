from bs4 import BeautifulSoup
from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from django.urls import reverse
from datetime import timedelta
from django.conf import settings
from uuid import uuid4

from .utils import hash_secret_key
from .models import (
    generate_domain_from_int,
    Domain,
    DomainNameHelper,
    Subdomain,
    RecordApiKey,
    Record,
    create_subdomain,
)
from .views import (
    list_domains,
    create_free_domain,
    describe_domain,
    describe_subdomain,
    delete_subdomain,
    add_subdomain,
    delete_api_key,
    create_api_key,
    create_record_api_key,
    create_resource_record,
    delete_resource_record,
)


class AlwaysSucceed(TestCase):
    def test_pass(self):
        pass


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


class WithUserTests(TestCase):
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
        response = self.client.get(self.target_url)
        self.assertRedirects(
            response, "/accounts/login/?next=" + self.target_url, status_code=302
        )

    def assert_redirects_to_login_when_logged_out_on_post(self):
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


class WithDomainTests(WithUserTests):
    def setUp(self):
        super().setUp()

        self.domain_name = "test-domain-name"
        self.domain = Domain.objects.create(
            name=self.domain_name,
            owner=self.testUser,
        )


class WithSubdomainTests(WithDomainTests):
    def setUp(self):
        super().setUp()

        self.subdomain_name = "test-subdomain-name"
        result = create_subdomain(self.domain, self.subdomain_name)
        self.subdomain = result.subdomain
        self.subdomain_key = result.keyObject
        self.subdomain_secret_key = result.secretKey


class ModelTests(WithUserTests):
    def test_domain_name_helper(self):
        a = DomainNameHelper.objects.create()
        b = DomainNameHelper.objects.create()

        self.assertLess(a.id, b.id)
        self.assertLess(a.get_name(), b.get_name())

    def test_domain(self):
        a = Domain.objects.create(
            name="abc",
            owner=self.testUser,
        )

        self.assertEqual("abc", a.name)
        self.assertEqual("abc", str(a))

        original_created = a.created.timestamp()
        original_updated = a.updated.timestamp()

        self.assertAlmostEqual(original_created, original_updated, delta=0.01)
        self.assertAlmostEqual(original_updated, timezone.now().timestamp(), delta=0.01)

        # Update the owner
        a.owner = self.wrongUser
        a.save()

        self.assertLess(original_updated, a.updated.timestamp())
        self.assertEqual(original_created, a.created.timestamp())

    def test_subdomain(self):
        my_domain = Domain.objects.create(
            name="abc",
            owner=self.testUser,
        )

        result = create_subdomain(my_domain, "mail")

        self.assertEqual("mail.abc", str(result.subdomain))
        self.assertEqual(self.testUser, result.subdomain.domain.owner)

        self.assertEqual(result.subdomain, result.keyObject.subdomain)
        self.assertEqual(my_domain, result.keyObject.subdomain.domain)
        self.assertEqual(self.testUser, result.keyObject.subdomain.domain.owner)

        self.assertEqual(
            hash_secret_key(result.secretKey), result.keyObject.hashedValue
        )


class TestListDomains(WithUserTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(list_domains)

    def test_list_domains(self):
        self.client.force_login(self.testUser)

        Domain.objects.create(
            name="foo",
            owner=self.testUser,
        )

        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create Free Domain")
        self.assertContains(response, "Manage")
        self.assertContains(response, "foo.localcert.net")

    def test_list_domains_empty(self):
        self.client.force_login(self.testUser)

        # No domains
        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create Free Domain")
        self.assertNotContains(response, "Manage")  # no domains to manage

    def test_limits(self):
        self.client.force_login(self.testUser)

        for i in range(settings.LOCALCERT_DOMAIN_LIMIT):
            # Max out the domains
            Domain.objects.create(
                name=str(i),
                owner=self.testUser,
            )

        response = self.client.get(self.target_url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Create Free Domain")  # can't create more
        self.assertContains(response, "Manage")
        for i in range(settings.LOCALCERT_DOMAIN_LIMIT):
            self.assertContains(response, f"{i}.localcert.net")

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_get()

    def test_wrong_user(self):
        # testUser has one domain
        domain_name = "cantseeme"
        Domain.objects.create(
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

        response = self.client.post(self.target_url, follow=True)

        domain = Domain.objects.filter(owner=self.testUser)
        self.assertEqual(len(domain), 1)
        domain = domain[0]

        self.assertContains(response, domain.name)
        self.assertRedirects(
            response, reverse(describe_domain, kwargs={"domain_id": domain.id})
        )

    def test_limits(self):
        self.client.force_login(self.testUser)

        for i in range(settings.LOCALCERT_DOMAIN_LIMIT):
            Domain.objects.create(
                name=str(i),
                owner=self.testUser,
            )

        response = self.client.post(self.target_url)
        self.assertContains(response, "Domain limit already reached", status_code=400)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        pass

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()
        self.assert_get_method_not_allowed()


class TestDescribeDomain(WithDomainTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(describe_domain, kwargs={"domain_id": self.domain.id})

    def test_describe_domain(self):
        self.client.force_login(self.testUser)
        response = self.client.get(self.target_url)
        self.assertContains(response, self.domain.name)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_get()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_get()

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()
        self.assert_post_method_not_allowed()


class TestDescribeSubdomain(WithSubdomainTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(
            describe_subdomain, kwargs={"subdomain_id": self.subdomain.id}
        )

    def test_descrive_subdomain(self):
        self.client.force_login(self.testUser)
        response = self.client.get(self.target_url)
        self.assertContains(response, self.domain.name)
        self.assertContains(response, self.subdomain.name)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_get()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_get()

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()
        self.assert_post_method_not_allowed()


class TestAddSubdomain(WithDomainTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(add_subdomain, kwargs={"domain_id": self.domain.id})
        self.subdomain_name = uuid4()
        self.request_body = {"subdomain": self.subdomain_name}

    def test_add_subdomain(self):
        self.client.force_login(self.testUser)
        response = self.client.post(
            self.target_url,
            data=self.request_body,
        )
        self.assertContains(
            response, f"{self.subdomain_name}.{self.domain.name}.localcert.net"
        )

        subdomain = Subdomain.objects.filter(
            domain=self.domain,
        )
        self.assertEqual(1, len(subdomain))
        subdomain = subdomain[0]

        # A single API key for this subdomain was created
        apiKey = RecordApiKey.objects.filter(
            subdomain=subdomain,
        )
        self.assertEqual(1, len(apiKey))
        apiKey = apiKey[0]
        self.assertIsNone(apiKey.last_used)
        self.assertContains(response, apiKey.id)

    def test_limits(self):
        for i in range(settings.LOCALCERT_SUBDOMAIN_LIMIT):
            Subdomain.objects.create(
                name=str(i),
                domain=self.domain,
            )

        self.client.force_login(self.testUser)
        response = self.client.post(
            self.target_url,
            data=self.request_body,
        )
        self.assertEqual(400, response.status_code)

    def test_existing(self):
        Subdomain.objects.create(
            name=self.subdomain_name,
            domain=self.domain,
        )

        self.client.force_login(self.testUser)
        response = self.client.post(
            self.target_url,
            data=self.request_body,
        )

        self.assertEqual(400, response.status_code)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_post()

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()
        self.assert_get_method_not_allowed()


class TestDeleteSubdomain(WithSubdomainTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(
            delete_subdomain, kwargs={"subdomain_id": self.subdomain.id}
        )

    def test_delete_subdomain(self):
        self.assertEqual(1, Subdomain.objects.filter(domain=self.domain).count())

        self.client.force_login(self.testUser)
        response = self.client.post(self.target_url, follow=True)
        self.assertRedirects(
            response, reverse(describe_domain, kwargs={"domain_id": self.domain.id})
        )
        self.assertNotContains(response, self.subdomain.name)

        self.assertEqual(0, Subdomain.objects.filter(domain=self.domain).count())

        # can't delete twice
        self.client.force_login(self.testUser)
        response = self.client.post(self.target_url)
        self.assertEqual(404, response.status_code)

    def test_delete_non_existing(self):
        target_url = reverse(delete_subdomain, kwargs={"subdomain_id": uuid4()})
        self.client.force_login(self.testUser)
        response = self.client.post(target_url)
        self.assertEqual(404, response.status_code)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_post()

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()
        self.assert_get_method_not_allowed()


class TestDeleteApiKey(WithSubdomainTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(
            delete_api_key, kwargs={"keyId": self.subdomain_key.id}
        )

    def test_delete_api_key(self):
        self.assertEqual(
            1, RecordApiKey.objects.filter(subdomain=self.subdomain).count()
        )

        self.client.force_login(self.testUser)

        # start delete process
        response = self.client.get(self.target_url)
        # should confirm the key we are deleting
        self.assertContains(response, self.domain.name)
        self.assertContains(response, self.subdomain.name)
        self.assertContains(response, self.subdomain_key.id)

        # actually delete it
        response = self.client.post(self.target_url, follow=True)
        self.assertNotContains(response, self.subdomain_key.id)
        self.assertRedirects(
            response,
            reverse(describe_subdomain, kwargs={"subdomain_id": self.subdomain.id}),
        )
        self.assertEqual(
            0, RecordApiKey.objects.filter(subdomain=self.subdomain).count()
        )

    def test_delete_non_existing(self):
        self.client.force_login(self.testUser)
        target_url = reverse(delete_api_key, kwargs={"keyId": uuid4()})

        response = self.client.get(target_url)
        self.assertEqual(404, response.status_code)

        response = self.client.post(target_url)
        self.assertEqual(404, response.status_code)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_get()
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_get()
        self.assert_404_when_logged_in_as_wrong_user_on_post()

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()


class TestCreateApiKey(WithSubdomainTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(
            create_api_key, kwargs={"subdomain_id": self.subdomain.id}
        )

    def test_create_api_key(self):
        self.client.force_login(self.testUser)

        response = self.client.post(self.target_url)
        self.assertContains(response, self.domain)
        self.assertContains(response, self.subdomain)

        apiKeys = RecordApiKey.objects.filter(subdomain=self.subdomain)
        self.assertEqual(2, len(apiKeys))

        # an API key will already exist, as one is created when the subdomain is created
        # find the new one we created in this test
        if apiKeys[0].id == self.subdomain_key.id:
            new_key = apiKeys[1]
        else:
            new_key = apiKeys[0]

        self.assertContains(response, new_key.id)

        # Deep check the content of the page
        soup = BeautifulSoup(response.content, features="html.parser")
        actualSecretKey = soup.find("td", id="secretKey").text
        actualSecretKeyId = soup.find("td", id="secretKeyId").text
        actualFQDN = soup.find("td", id="fqdn").text
        self.assertEqual(actualSecretKeyId, str(new_key.id))
        self.assertEqual(hash_secret_key(actualSecretKey), new_key.hashedValue)
        self.assertEqual(
            actualFQDN, f"{self.subdomain.name}.{self.domain.name}.localcert.net"
        )

    def test_limits(self):
        while (
            RecordApiKey.objects.filter(subdomain=self.subdomain).count()
            < settings.LOCALCERT_API_KEYS_PER_SUBDOMAIN_LIMIT
        ):
            create_record_api_key(self.subdomain)

        self.client.force_login(self.testUser)

        response = self.client.post(self.target_url)
        self.assertContains(response, "limit reached", status_code=400)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_post()

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()
        self.assert_get_method_not_allowed()


class TestListResourceRecord(WithSubdomainTests):
    def setUp(self):
        super().setUp()
        # We don't have a dedicated record list, use the subdomain detail page instead
        self.target_url = reverse(
            describe_subdomain, kwargs={"subdomain_id": self.subdomain.id}
        )

    def test_list_records_empty(self):
        self.client.force_login(self.testUser)

        response = self.client.get(self.target_url)
        self.assertContains(response, "No DNS records exist")
        self.assertContains(response, "Add Record")

    def test_list_single_record(self):
        self.client.force_login(self.testUser)

        record_value = uuid4()
        Record.objects.create(
            subdomain=self.subdomain,
            value=record_value,
        )

        response = self.client.get(self.target_url)
        self.assertContains(response, record_value)
        self.assertNotContains(response, "No DNS records exist")
        self.assertContains(response, "Add Record")

    def test_list_max_records(self):
        self.client.force_login(self.testUser)

        for i in range(settings.LOCALCERT_RECORDS_PER_SUBDOMAIN_LIMIT):
            Record.objects.create(
                subdomain=self.subdomain,
                value=f"subdomain-{i}",
            )

        response = self.client.get(self.target_url)
        for i in range(settings.LOCALCERT_RECORDS_PER_SUBDOMAIN_LIMIT):
            self.assertContains(response, f"subdomain-{i}")
        self.assertNotContains(response, "No DNS records exist")
        self.assertNotContains(response, "Add Record")


class TestCreateResourceRecord(WithSubdomainTests):
    def setUp(self):
        super().setUp()
        self.target_url = reverse(
            create_resource_record, kwargs={"subdomain_id": self.subdomain.id}
        )
        self.record_value = "ThisIsMyValue"
        self.request_body = {"value": self.record_value}

    def test_create_resource_record(self):
        self.client.force_login(self.testUser)

        response = self.client.get(self.target_url)
        self.assertContains(response, "_acme-challenge")
        self.assertContains(response, self.domain.name)
        self.assertContains(response, self.subdomain.name)

        response = self.client.post(self.target_url, self.request_body, follow=True)
        expected_redirect = reverse(
            describe_subdomain,
            kwargs={
                "subdomain_id": self.subdomain.id,
            },
        )
        self.assertRedirects(response, expected_redirect)
        self.assertContains(response, "_acme-challenge")
        self.assertContains(response, self.record_value)

    def test_limits(self):
        self.client.force_login(self.testUser)

        for i in range(settings.LOCALCERT_RECORDS_PER_SUBDOMAIN_LIMIT):
            Record.objects.create(
                subdomain=self.subdomain,
                value=str(i),
            )

        response = self.client.post(self.target_url, self.request_body)
        self.assertContains(response, "limit reached", status_code=400)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_get()
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_get()
        self.assert_404_when_logged_in_as_wrong_user_on_post()

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()


class TestDeleteResourceRecord(WithSubdomainTests):
    def setUp(self):
        super().setUp()
        self.record_value = "ThisIsTheValue"
        self.record = Record.objects.create(
            subdomain=self.subdomain,
            value=self.record_value,
        )
        self.target_url = reverse(
            delete_resource_record,
            kwargs={"record_id": self.record.id},
        )

    def test_delete_resource_record(self):
        self.client.force_login(self.testUser)

        expected_redirect = reverse(
            describe_subdomain, kwargs={"subdomain_id": self.subdomain.id}
        )
        response = self.client.get(expected_redirect)
        self.assertContains(response, self.record_value)

        response = self.client.post(self.target_url, follow=True)
        self.assertRedirects(response, expected_redirect)
        self.assertContains(response, self.domain.name)
        self.assertContains(response, self.subdomain.name)
        self.assertNotContains(response, self.record_value)

    def test_delete_non_existing(self):
        self.client.force_login(self.testUser)
        target_url = reverse(
            delete_resource_record,
            kwargs={"record_id": uuid4()},
        )
        response = self.client.post(target_url)
        self.assertEqual(404, response.status_code)

    def test_logged_out(self):
        self.assert_redirects_to_login_when_logged_out_on_get()
        self.assert_redirects_to_login_when_logged_out_on_post()

    def test_wrong_user(self):
        self.assert_404_when_logged_in_as_wrong_user_on_get()
        self.assert_404_when_logged_in_as_wrong_user_on_post()

    def test_wrong_method(self):
        self.assert_head_method_not_allowed()
