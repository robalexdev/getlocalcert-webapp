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
