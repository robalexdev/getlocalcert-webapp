import logging
from typing import Dict

from django.contrib.auth.models import AbstractUser
from django.http import (
    HttpResponse,
    JsonResponse,
)
from django.urls import reverse
from urllib.parse import urlencode

from domains.constants import DOMAIN_PER_STAFF_LIMIT, DOMAIN_PER_USER_LIMIT


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
        logging.error(f"Unable to process request: {self.message}")
        return HttpResponse("Unable to process request", status=self.status_code)

    def render_json(self):
        assert self.status_code >= 500
        logging.error(f"Unable to process request: {self.message}")
        return JsonResponse(
            {
                "error": "Unable to process request",
            },
            status=self.status_code,
        )


def build_url(*args, **kwargs):
    params = kwargs.pop("params", {})
    url = reverse(*args, **kwargs)
    if params:
        url += "?" + urlencode(params)
    return url


def sort_records_key(record: Dict[str, str]) -> str:
    """
    Sort records so that:
      User modifiable come first
      Records are sorted by type
      Then name
    """
    rr_type = record["type"]
    name = record["name"]
    is_user_modifiable = rr_type == "TXT" and name.startswith("_acme-challenge.")
    return f"{0 if is_user_modifiable else 1} {rr_type} {name}"


def domain_limit_for_user(user: AbstractUser):
    if user.is_staff:
        return DOMAIN_PER_STAFF_LIMIT
    return DOMAIN_PER_USER_LIMIT


def remove_trailing_dot(dn: str) -> str:
    if dn.endswith("."):
        return dn[:-1]
    return dn


SUPPORTED_DOMAINS = [
    "localcert.net",
    "localhostcert.net",
    "corpnet.work",
]


def parent_zone_name(value: str, soft_error: bool = False) -> str:
    value = remove_trailing_dot(value)
    for suffix in SUPPORTED_DOMAINS:
        if value.endswith(f".{suffix}"):
            return suffix
    assert soft_error
    return "Zone"


def subdomain_name(value: str) -> str:
    value = remove_trailing_dot(value)
    for suffix in SUPPORTED_DOMAINS:
        if value.endswith(f".{suffix}"):
            return value.removesuffix(f".{suffix}")
    assert False  # pragma: no cover
