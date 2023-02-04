import logging
from base64 import urlsafe_b64decode

from django.http import HttpResponseBadRequest, HttpResponseServerError


ACME_CHALLENGE_LABEL = "_acme-challenge"


class CustomException(Exception):
    def __init__(self, message):
        self.message = message


class CustomExceptionBadRequest(CustomException):
    def render(self):
        return HttpResponseBadRequest(self.message)


class CustomExceptionServerError(CustomException):
    def render(self):
        logging.error(self.message)
        return HttpResponseServerError("Unable to process request")


def with_dot_suffix(domain: str) -> str:
    """
    Domain name with the dot for root
    example.com -> example.com.
    """
    if domain.endswith("."):
        return domain
    return f"{domain}."


def without_dot_suffix(domain: str) -> str:
    """
    Domain name without the dot for root
    example.com. -> example.com
    """
    if domain.endswith("."):
        return domain[0:-1]
    return domain


def validate_acme_dns01_txt_value(value: str):
    """
    We're only going to support an ACME DNS challenge response here
    """
    # Must be base64url encoded
    # https://datatracker.ietf.org/doc/html/draft-ietf-acme-acme-01#section-7.5

    if "+" in value or "/" in value:
        raise CustomExceptionBadRequest(
            "ACME DNS-01 challenge response must be base64url encoded (not base64)"
        )

    if "=" in value:
        raise CustomExceptionBadRequest(
            "ACME DNS-01 challenge response must not use padding (remove trailing =)"
        )

    # add the padding back
    modlen = len(value) % 4
    if modlen == 2:
        value += "=="
    elif modlen == 3:
        value += "="

    try:
        raw = urlsafe_b64decode(value)
    except Exception:
        raise CustomExceptionBadRequest(
            "ACME DNS-01 must be base64url encoded (decode failed)"
        )

    # raw must be sha256(challenge + thumbprint)
    if len(raw) != 32:
        raise CustomExceptionBadRequest(
            "ACME DNS-01 must be SHA-256 hashed (incorrect length)"
        )

    # Otherwise the value is a randomized hash, looks good.
    return
