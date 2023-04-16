from .validators import TxtRecordValueValidator, ZoneNameValidator
from django import forms


class ZoneNameField(forms.CharField):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.validators.append(ZoneNameValidator())


class UuidField(forms.RegexField):
    def __init__(self, **kwargs):
        super().__init__(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", **kwargs
        )


class TxtRecordValueField(forms.CharField):
    def __init__(self, **kwargs):
        super().__init__(label="Record Value", **kwargs)
        self.validators.append(TxtRecordValueValidator())


class CreateZoneApiKeyForm(forms.Form):
    zone_name = ZoneNameField()


class DescribeZoneForm(forms.Form):
    zone_name = ZoneNameField()


class AddRecordForm(forms.Form):
    zone_name = ZoneNameField(label="Domain Name", widget=forms.HiddenInput)
    rr_content = TxtRecordValueField()


class DeleteRecordForm(forms.Form):
    zone_name = ZoneNameField(label="Domain Name", widget=forms.HiddenInput)
    rr_content = TxtRecordValueField(widget=forms.HiddenInput)


class DeleteZoneApiKeyForm(forms.Form):
    secret_key_id = UuidField(label="Secret key ID")
