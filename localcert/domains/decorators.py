import base64
import binascii
import django.utils.timezone
import functools

from .models import (
    ZoneApiKey,
)
from .utils import (
    CustomException,
    CustomExceptionBadRequest,
)
from django.http import (
    HttpRequest,
)


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

        # Prefer keys in the header, acme-dns style
        if KEY_FIELD_NAME in request.headers:
            if USER_FIELD_NAME in request.headers:
                providedKeyId = request.headers[USER_FIELD_NAME]
                providedSecretKey = request.headers[KEY_FIELD_NAME]
            else:
                # Require both
                raise CustomExceptionBadRequest(
                    f"Missing required header {USER_FIELD_NAME}"
                )
        else:
            # fall back to HTTP basic auth (OpenAPI compatibility)
            auth_header = request.META.get("HTTP_AUTHORIZATION", "")
            if auth_header:
                token_type, _, credentials = auth_header.partition(" ")
                if token_type != "Basic":
                    raise CustomExceptionBadRequest("HTTP basic auth type unsupported")
                try:
                    credentials = base64.b64decode(credentials, validate=True).decode(
                        "utf-8"
                    )
                except binascii.Error:
                    raise CustomExceptionBadRequest(
                        "HTTP basic auth base64 decode error"
                    )
                providedKeyId, _, providedSecretKey = credentials.partition(":")
                if not providedKeyId or not providedSecretKey:
                    raise CustomExceptionBadRequest(
                        "HTTP basic auth missing credentials"
                    )
            else:
                raise CustomExceptionBadRequest(
                    f"Missing required header {KEY_FIELD_NAME} or HTTP basic auth"
                )

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


class require_hostname:
    def __init__(self, required_hostname: str):
        self.required_hostname = required_hostname

    def __call__(self, fn):
        def check(request: HttpRequest, *args, **kwargs):
            actual_hostname = request.get_host()
            if actual_hostname != self.required_hostname:
                raise CustomExceptionBadRequest("Not Found", status_code=404)
            return fn(request, *args, **kwargs)

        return check
