import secrets
import string
import uuid

from django.db import models
from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
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

    created = models.DateTimeField(default=timezone.now)
    updated = models.DateTimeField(auto_now=True)
    is_delegate = models.BooleanField(default=False)

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
