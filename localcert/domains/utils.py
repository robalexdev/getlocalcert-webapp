import logging
import secrets

from base64 import urlsafe_b64decode
from hashlib import sha256

from django.http import (
    HttpResponse,
    JsonResponse,
)


class CustomException(Exception):
    pass


class CustomExceptionBadRequest(CustomException):
    """
    When the client provides bad input, give the user a detailed 4xx response
    """

    def __init__(self, message, status_code=400):
        self.message = message
        self.status_code = status_code

    def render(self):
        assert self.status_code >= 400 and self.status_code < 500
        return HttpResponse(self.message, status=self.status_code)

    def render_json(self):
        assert self.status_code >= 400 and self.status_code < 500
        return JsonResponse(
            {
                "error": self.message,
            },
            status=self.status_code,
        )


class CustomExceptionServerError(CustomException):
    """
    When there's a server side error, log it and give the user a vague 5xx response
    """

    def __init__(self, message, status_code=500):
        self.message = message
        self.status_code = status_code

    def render(self):
        assert self.status_code >= 500
        logging.error(self.message)
        return HttpResponse("Unable to process request", status=self.status_code)

    def render_json(self):
        assert self.status_code >= 500
        logging.error(self.message)
        return JsonResponse(
            {
                "error": "Unable to process request",
            },
            status=self.status_code,
        )


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


def create_secret() -> str:
    return secrets.token_hex()


def hash_secret(secret: str) -> str:
    return sha256(secret.encode("utf-8")).digest()
