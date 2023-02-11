from base64 import urlsafe_b64encode
from django.forms import ValidationError
from django.test import TestCase
from domains.test_utils import randomDns01ChallengeResponse
from domains.validators import validate_acme_dns01_txt_value


class ValidateAcmeDnsTxtRecord(TestCase):
    def test_valid_record(self):
        validate_acme_dns01_txt_value(randomDns01ChallengeResponse())

    def test_invalid_record(self):
        # too short
        with self.assertRaisesMessage(ValidationError, "incorrect length"):
            validate_acme_dns01_txt_value(urlsafe_b64encode(b"123").decode("utf-8"))

        # too long
        with self.assertRaisesMessage(ValidationError, "incorrect length"):
            validate_acme_dns01_txt_value(
                randomDns01ChallengeResponse() + randomDns01ChallengeResponse()
            )

        # wrong encoding
        with self.assertRaisesMessage(ValidationError, "base64"):
            validate_acme_dns01_txt_value("abc+")

        # invalid character set
        with self.assertRaisesMessage(ValidationError, "(decode failed)"):
            validate_acme_dns01_txt_value(" ")

        # no padding
        with self.assertRaisesMessage(ValidationError, "must not use padding"):
            validate_acme_dns01_txt_value(urlsafe_b64encode(b"1234").decode("utf-8"))
