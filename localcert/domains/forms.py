from .models import Zone
from .validators import TxtRecordValueValidator, ZoneNameValidator, LabelValidator
from django import forms


class ZoneNameField(forms.CharField):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.validators.append(ZoneNameValidator())


class LabelField(forms.CharField):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.validators.append(LabelValidator(ban_words=True))


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


class RegisterSubdomain(forms.Form):
    subdomain = LabelField()
    parent_zone = forms.ChoiceField(
        choices=(
            ("localhostcert.net.", "localhostcert.net"),
            ("localcert.net.", "localcert.net"),
        ),
    )

    def clean(self):
        subdomain_name = self.cleaned_data.get("subdomain")
        parent_zone = self.cleaned_data.get("parent_zone")
        if subdomain_name is not None and parent_zone is not None:
            zone_name = subdomain_name + "." + parent_zone
            self.cleaned_data["zone_name"] = zone_name

            zone_count = Zone.objects.filter(
                name=zone_name,
            ).count()
            if zone_count > 0:
                self.add_error("subdomain", "Subdomain already registered")


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
