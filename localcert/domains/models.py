import string
import secrets
import hashlib
import uuid

from django.db import models
from django.conf import settings


class Domain(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    name = models.CharField(
        max_length=8,  # roughly 36**8 = 3 trillion domains
        editable=False,
        unique=True,
    )

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        # When a user deletes a domain, keep it for a while before finally purging it
        # This will ensure that any valid TLS certificates will expire before the domain is reused
        on_delete=models.SET_NULL,
        null=True,
        editable=False,
    )

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.get_name()


class DomainNameHelper(models.Model):
    id = models.BigAutoField(
        primary_key=True,
        editable=False,
        unique=True,
    )

    # autoincrement -> short domain label function
    def get_name(self) -> str:
        return generate_domain_from_int(int(self.id))


DOMAIN_LABEL_CHARS = string.digits + string.ascii_lowercase


def generate_domain_from_int(i: int) -> str:
    label = ""
    while True:
        label = DOMAIN_LABEL_CHARS[i % len(DOMAIN_LABEL_CHARS)] + label
        print("   ", label)
        i = i // len(DOMAIN_LABEL_CHARS)
        if i < 1:
            break
        i -= 1
    return label


class Subdomain(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    name = models.CharField(
        max_length=255,
        null=False,
        blank=False,
        editable=True,
    )
    domain = models.ForeignKey(
        Domain,
        related_name="subdomains",
        on_delete=models.CASCADE,
        null=False,
        editable=False,
    )
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)


class RecordApiKey(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    hashedValue = models.CharField(
        max_length=255,
        null=False,
        blank=False,
        editable=False,
    )
    subdomain = models.ForeignKey(
        Subdomain,
        related_name="apiKeys",
        on_delete=models.CASCADE,
        null=True,
        default=None,
        editable=False,
    )
    created = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(
        default=None,
        null=True,
        blank=False,
        editable=False,
    )

    def id_str(self):
        return str(self.id)


class CreateSubdomainResult:
    def __init__(self, subdomain: Subdomain, keyObject: RecordApiKey, secretKey: str):
        self.subdomain = subdomain
        self.keyObject = keyObject
        self.secretKey = secretKey


def create_subdomain(domain: Domain, name: str) -> CreateSubdomainResult:
    subdomain, created = Subdomain.objects.get_or_create(
        name=name,
        domain=domain,
    )
    if not created:
        return None

    # add a key
    keyObject, secretKey = create_record_api_key(subdomain)
    return CreateSubdomainResult(subdomain, keyObject, secretKey)


def create_record_api_key(subdomain: Subdomain) -> tuple[RecordApiKey, str]:
    secretKey = secrets.token_hex()
    digest = hashlib.sha256()
    digest.update(secretKey.encode("utf-8"))
    hashOfSecretKey = digest.hexdigest()

    keyObject = RecordApiKey.objects.create(
        hashedValue=hashOfSecretKey,
        subdomain=subdomain,
    )

    return keyObject, secretKey


def change_subdomain_api_key(
    subdomain: Subdomain, is_first_key: bool
) -> tuple[RecordApiKey, str]:
    keyObject, secretKey = create_record_api_key()
    if is_first_key:
        if subdomain.apiKeyOne:
            subdomain.apiKeyOne.delete()
        subdomain.apiKeyOne = keyObject
    else:
        if subdomain.apiKeyTwo:
            subdomain.apiKeyTwo.delete()
        subdomain.apiKeyTwo = keyObject
    subdomain.save()
    return keyObject, secretKey


class Record(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    value = models.CharField(
        max_length=255,
        null=False,
        blank=False,
        editable=True,
    )
    subdomain = models.ForeignKey(
        Subdomain,
        related_name="records",
        on_delete=models.CASCADE,
        null=False,
        editable=False,
    )
    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)
