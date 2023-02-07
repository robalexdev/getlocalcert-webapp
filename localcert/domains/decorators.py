import functools
import logging
import re

from string import ascii_uppercase
from typing import List
from .utils import (
    CustomException,
    CustomExceptionBadRequest,
    with_dot_suffix,
)
from django.http import (
    HttpRequest,
)
import django.utils.timezone

from .models import (
    Zone,
    ZoneApiKey,
)


# Don't allow uppercase at the API level
DNS_LABEL_RE = re.compile("^[-.a-z0-9]+$")
DNS_TXT_LABEL_RE = re.compile("^[-._a-z0-9]+$")  # includes _


def validate_rrname(rrname: str, isTXT: bool):
    if len(rrname) > 253:
        raise CustomExceptionBadRequest("rrname too long")
    if len(rrname) == 0:
        raise CustomExceptionBadRequest("rrname cannot be empty")

    if any([c in ascii_uppercase for c in rrname]):
        raise CustomExceptionBadRequest("use lowercase rrname")

    if isTXT:
        match = DNS_TXT_LABEL_RE.match(rrname)
    else:
        match = DNS_LABEL_RE.match(rrname)
    if match is None:
        raise CustomExceptionBadRequest("rrname has invalid characters")

    parts = rrname[0:-1].split(".")
    for part in parts:
        if len(part) == 0:
            raise CustomExceptionBadRequest("label cannot be empty")
        elif len(part) > 63:
            raise CustomExceptionBadRequest("label too long")
        elif part.startswith("-"):
            raise CustomExceptionBadRequest("label cannot start with hyphen")
        elif part.endswith("-"):
            raise CustomExceptionBadRequest("label cannot end with hyphen")
        elif "--" in part:
            raise CustomExceptionBadRequest(
                "label cannot have multiple hyphens in a row"
            )

    # Only suffix supported currently
    if not rrname.endswith(".localhostcert.net."):
        raise CustomExceptionBadRequest("Only localhostcert.net is supported")
    rrname_parts = rrname.split(".")
    if len(rrname_parts) < 4:
        raise CustomExceptionBadRequest(
            "rrname should use the form <domain>.localhostcert.net"
        )


def parse_rrname(rrname: str, isTXT: bool) -> str:
    validate_rrname(rrname, isTXT)
    rrname_parts = rrname.split(".")
    return ".".join(rrname_parts[-4:])


def permitted_in_POST(
    required_args: List[str],
    optional_args: List[str] = [],
    allow_unexpected: bool = False,
):
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs):
            for required in required_args:
                if required not in request.POST:
                    logging.debug(f"Missing {required}")
                    raise CustomExceptionBadRequest(
                        f"Missing required input: {required}"
                    )
            for actual_arg in request.POST.keys():
                if (
                    actual_arg not in required_args
                    and actual_arg not in optional_args
                    and not allow_unexpected
                ):
                    # TODO: safely report which is unexpected
                    # logging.debug(f"Unexpected: {actual_arg}")
                    raise CustomExceptionBadRequest("Unexpected input")

            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def require_zone_access(zonekw: str, isTXT: bool = False):
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs):
            assert zonekw in kwargs
            name = kwargs[zonekw]
            name = with_dot_suffix(name)

            domain_name = parse_rrname(name, isTXT)
            if zonekw == "zone_name" and domain_name != name:
                # must be an exact match
                raise CustomExceptionBadRequest("Invalid domain")

            domain = Zone.objects.filter(
                name=domain_name,
                owner=request.user,
            ).first()
            if not domain:
                raise CustomExceptionBadRequest(
                    "Domain does not exist, or you are not the owner", status_code=404
                )

            # TODO: ensure this isn't set, or ideally, no unexpected keys are set
            kwargs["validated_zone"] = domain
            # add this back with_dot_suffix
            kwargs[zonekw] = name
            return view_func(request, *args, **kwargs)

        return wrapper

    return decorator


def use_custom_errors(view_fn):
    @functools.wraps(view_fn)
    def fn(*args, **kwargs):
        try:
            return view_fn(*args, **kwargs)
        except CustomException as e:
            return e.render()

    return fn


def use_custom_json_errors(view_fn):
    @functools.wraps(view_fn)
    def fn(*args, **kwargs):
        try:
            return view_fn(*args, **kwargs)
        except CustomException as e:
            return e.render_json()

    return fn


# See https://github.com/joohoi/acme-dns#update-endpoint
def require_api_key(view_fn):
    @functools.wraps(view_fn)
    def fn(request: HttpRequest, *args, **kwargs):
        KEY_FIELD_NAME = "X-Api-Key"
        USER_FIELD_NAME = "X-Api-User"

        if KEY_FIELD_NAME not in request.headers:
            raise CustomExceptionBadRequest(f"Missing required header {KEY_FIELD_NAME}")
        if USER_FIELD_NAME not in request.headers:
            raise CustomExceptionBadRequest(
                f"Missing required header {USER_FIELD_NAME}"
            )

        providedKeyId = request.headers[USER_FIELD_NAME]
        providedSecretKey = request.headers[KEY_FIELD_NAME]

        foundKey = ZoneApiKey.objects.filter(id=providedKeyId).first()
        if foundKey is not None and foundKey.check_secret_key(providedSecretKey):
            # Track the use of the key
            foundKey.last_used = django.utils.timezone.now()
            foundKey.save()

            kwargs["authenticated_key"] = foundKey
            return view_fn(request, *args, **kwargs)
        else:
            raise CustomExceptionBadRequest("Unauthorized", status_code=401)

    return fn
