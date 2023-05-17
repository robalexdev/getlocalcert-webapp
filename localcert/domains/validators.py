import binascii
import re

from base64 import b64decode
from django.core import validators
from django.forms import ValidationError
from string import ascii_uppercase

from .banned_words import banned_words


# Don't allow uppercase at the API level
DNS_LABEL_RE = re.compile("^[-a-z0-9]+$")


def validate_label(ban_words: bool, label: str):
    if len(label) == 0:
        raise ValidationError("Domain label cannot be empty")
    if len(label) > 63:
        raise ValidationError("Domain label is too long")
    if label.startswith("-"):
        raise ValidationError("Domain label cannot start with hyphen")
    if label.endswith("-"):
        raise ValidationError("Domain label cannot end with hyphen")
    if "--" in label:
        raise ValidationError("Domain label cannot have multiple hyphens in a row")
    if "." in label:
        raise ValidationError("Domain label cannot contain a '.'")
    if ban_words and label in banned_words:
        raise ValidationError(
            "Domain label is on a blocklist, please choose a different name"
        )
    if any([upper in label for upper in ascii_uppercase]):
        raise ValidationError("Domain label should use lowercase")
    match = DNS_LABEL_RE.match(label)
    if match is None:
        raise ValidationError("Domain label has invalid characters")


def validate_zone_name(ban_words: bool, zone_name: str):
    if len(zone_name) > 253:
        raise ValidationError("Domain name too long")
    if len(zone_name) == 0:  # pragma: no cover
        # Usually handled by required field check
        raise ValidationError("Domain name cannot be empty")

    labels = zone_name[0:-1].split(".")
    for label in labels:
        validate_label(ban_words, label)
    if len(labels) != 3:
        raise ValidationError(
            "Domain name should use the form <subdomain>.localhostcert.net or <subdomain>.localcert.net"
        )

    # Only suffix supported currently
    if not zone_name.endswith(".localhostcert.net.") and not zone_name.endswith(
        ".localcert.net."
    ):
        raise ValidationError(
            "Only domains under localhostcert.net or localcert.net are supported"
        )


def validate_acme_dns01_txt_value(value: str):
    """
    We're only going to support an ACME DNS challenge response here
    """
    # Must be base64url encoded
    # https://datatracker.ietf.org/doc/html/draft-ietf-acme-acme-01#section-7.5

    if "+" in value or "/" in value:
        raise ValidationError(
            "ACME DNS-01 challenge response must be base64url encoded (not base64). "
            + "If you're just testing, try 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
        )

    if "=" in value:
        raise ValidationError(
            "ACME DNS-01 challenge response must not use padding (remove trailing =). "
            + " If you're just testing, try 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
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
            "ACME DNS-01 challenge response must be base64url encoded (decode failed). "
            + "If you're just testing try 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
        )

    # raw must be sha256(challenge + thumbprint)
    if len(raw) != 32:
        raise ValidationError(
            "ACME DNS-01 challenge response must be SHA-256 hashed (incorrect length). "
            + "If you're just testing try 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
        )

    # Otherwise the value is a randomized hash, looks good.
    return


class ZoneNameValidator(validators.BaseValidator):
    def __init__(self):
        pass

    def __call__(self, value):
        validate_zone_name(ban_words=False, zone_name=value)


class LabelValidator(validators.BaseValidator):
    def __init__(self, ban_words):
        self.ban_words = ban_words

    def __call__(self, value):
        validate_label(ban_words=self.ban_words, label=value)


class TxtRecordValueValidator(validators.BaseValidator):
    def __init__(self):
        pass

    def __call__(self, value):
        validate_acme_dns01_txt_value(value)
