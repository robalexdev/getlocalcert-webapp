import logging

from django.http import (
    HttpResponse,
    JsonResponse,
)
from django.urls import reverse
from urllib.parse import urlencode


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
