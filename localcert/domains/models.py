import string
import uuid

from django.db import models
from django.conf import settings


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
        i = i // len(DOMAIN_LABEL_CHARS)
        if i < 1:
            break
        i -= 1
    return label
