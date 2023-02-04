import functools
import re

from string import ascii_uppercase
from .utils import CustomException, CustomExceptionBadRequest, with_dot_suffix
from django.http import (
    Http404,
    HttpResponseServerError,
    HttpResponseBadRequest,
)

from .models import (
    Zone,
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


def require_zone_access(zonekw: str, isTXT: bool = False):
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if zonekw not in kwargs:
                return HttpResponseBadRequest(f"Missing {zonekw}")
            name = kwargs[zonekw]
            name = with_dot_suffix(name)

            domain_name = parse_rrname(name, isTXT)
            if zonekw == "zone_name" and domain_name != name:
                # must be an exact match
                return HttpResponseBadRequest("Invalid domain")

            domain_list = Zone.objects.filter(
                name=domain_name,
                owner=request.user,
            )
            domain_list = [_ for _ in domain_list]
            if not domain_list:
                raise Http404("Domain does not exist, or you are not the owner")
            if len(domain_list) > 1:
                return HttpResponseServerError("Unable to process request")

            kwargs["validated_zone"] = domain_list[0]
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
