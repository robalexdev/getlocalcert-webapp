import binascii
import re

from base64 import b64decode
from django.core import validators
from django.forms import ValidationError
from string import ascii_uppercase


# Don't allow uppercase at the API level
DNS_LABEL_RE = re.compile("^[-.a-z0-9]+$")


def validate_label(label: str):
    if len(label) == 0:
        raise ValidationError("Domain label cannot be empty")
    elif len(label) > 63:
        raise ValidationError("Domain label too long")
    elif label.startswith("-"):
        raise ValidationError("Domain label cannot start with hyphen")
    elif label.endswith("-"):
        raise ValidationError("Domain label cannot end with hyphen")
    elif "--" in label:
        raise ValidationError("Domain label cannot have multiple hyphens in a row")


def validate_zone_name(zone_name: str):
    if len(zone_name) > 253:
        raise ValidationError("Domain name too long")
    if len(zone_name) == 0:
        raise ValidationError("Domain name cannot be empty")

    if any([c in ascii_uppercase for c in zone_name]):
        raise ValidationError("Use lowercase domain name")

    match = DNS_LABEL_RE.match(zone_name)
    if match is None:
        raise ValidationError("Domain name has invalid characters")

    labels = zone_name[0:-1].split(".")
    for label in labels:
        validate_label(label)
    if len(labels) != 3:
        raise ValidationError("Domain should use the form <domain>.localhostcert.net")

    # Only suffix supported currently
    if not zone_name.endswith(".localhostcert.net."):
        raise ValidationError("Only domains under localhostcert.net are supported")


def validate_acme_dns01_txt_value(value: str):
    """
    We're only going to support an ACME DNS challenge response here
    """
    # Must be base64url encoded
    # https://datatracker.ietf.org/doc/html/draft-ietf-acme-acme-01#section-7.5

    if "+" in value or "/" in value:
        raise ValidationError(
            "ACME DNS-01 challenge response must be base64url encoded (not base64)"
        )

    if "=" in value:
        raise ValidationError(
            "ACME DNS-01 challenge response must not use padding (remove trailing =)"
        )

    # add the padding back
    modlen = len(value) % 4
    if modlen == 2:
        value += "=="
    elif modlen == 3:
        value += "="

    # convert to normal base64
    value = value.replace("-", "+").replace("_", "/")

    try:
        raw = b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError):
        raise ValidationError(
            "ACME DNS-01 challenge response must be base64url encoded (decode failed)"
        )

    # raw must be sha256(challenge + thumbprint)
    if len(raw) != 32:
        raise ValidationError(
            "ACME DNS-01 challenge response must be SHA-256 hashed (incorrect length)"
        )

    # Otherwise the value is a randomized hash, looks good.
    return


class LabelValidator(validators.BaseValidator):
    def __init__(self):
        pass

    def __call__(self, value):
        validate_label(value)


class ZoneNameValidator(validators.BaseValidator):
    def __init__(self):
        pass

    def __call__(self, value):
        validate_zone_name(value)


class TxtRecordValueValidator(validators.BaseValidator):
    def __init__(self):
        pass

    def __call__(self, value):
        validate_acme_dns01_txt_value(value)
