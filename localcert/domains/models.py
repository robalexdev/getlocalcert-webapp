import secrets
import string
from typing import Dict
import uuid

from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from hashlib import sha256


class User(AbstractUser):
    pass


class Zone(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    name = models.CharField(
        # https://devblogs.microsoft.com/oldnewthing/20120412-00/?p=7873
        max_length=253,
        editable=False,
        unique=True,
    )
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        # If the owner is deleted, keep the domain around to prevent reuse
        # The old owner may still have TLS certs, so wait at least 90 days for those to expire
        on_delete=models.SET_NULL,
        null=True,
        editable=False,
    )

    created = models.DateTimeField(auto_now_add=True)
    updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


class ZoneApiKey(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    zone = models.ForeignKey(
        Zone,
        on_delete=models.CASCADE,
        null=False,
        editable=False,
    )

    hash = models.BinaryField(
        max_length=32,  # SHA256->32 bytes
        editable=False,
    )

    created = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(default=None, null=True)

    def check_secret_key(self, provided_secret_key: str) -> bool:
        return self.hash.tobytes() == hash_secret(provided_secret_key)

    @classmethod
    def create(cls, zone: Zone):
        secret_key = create_secret()
        obj = ZoneApiKey.objects.create(
            zone=zone,
            hash=hash_secret(secret_key),
        )
        return obj, secret_key


DOMAIN_LABEL_CHARS = string.digits + string.ascii_lowercase


def create_secret() -> str:
    return secrets.token_hex()


def hash_secret(secret: str) -> str:
    return sha256(secret.encode("utf-8")).digest()


class InstantSubdomainCreatedInfo:
    PARENT_DOMAIN = "localhostcert.net."

    def __init__(self, username, password, subdomain):
        self.username = username
        self.password = password
        self.subdomain = subdomain

    def get_fulldomain(self) -> str:
        return f"{self.subdomain}.{InstantSubdomainCreatedInfo.PARENT_DOMAIN}"

    def get_config(self) -> Dict[str, str]:
        return {
            "username": self.username,
            "password": self.password,
            "fulldomain": self.get_fulldomain(),
            "subdomain": self.subdomain,
            "allowfrom": [],
        }


def create_instant_subdomain() -> InstantSubdomainCreatedInfo:
    subdomain_name = str(uuid.uuid4())
    new_fqdn = subdomain_name + InstantSubdomainCreatedInfo.PARENT_DOMAIN
    new_zone = Zone.objects.create(
        name=new_fqdn,
        owner=None,
    )
    zone_key, secret = ZoneApiKey.create(new_zone)

    return InstantSubdomainCreatedInfo(
        subdomain=subdomain_name,
        username=str(zone_key.id),
        password=secret,
    )
