import json
import logging
import uuid

from enum import Enum
from typing import Dict

from .constants import (
    ACME_CHALLENGE_LABEL,
    API_ENDPOINT_BASE,
)
from .models import ManagedDomainName, Zone, ZoneApiKey
from .utils import remove_trailing_dot


class Credentials:
    def __init__(self, username: str, password: str, subdomain: str, fulldomain: str):
        assert fulldomain.startswith(f"{subdomain}.")
        self.username = username
        self.password = password
        self.subdomain = subdomain
        self.fulldomain = fulldomain

    def get_config(self) -> Dict[str, str]:
        return {
            "username": self.username,
            "password": self.password,
            "fulldomain": remove_trailing_dot(self.fulldomain),
            "subdomain": self.subdomain,
            # See: https://github.com/joohoi/acme-dns/issues/341
            "server_url": API_ENDPOINT_BASE,
            "allowfrom": [],
        }

    def get_config_json(self) -> str:
        return json.dumps(self.get_config(), indent=2)

    def get_lego_config(self) -> Dict[str, str]:
        return {
            remove_trailing_dot(self.fulldomain): self.get_config(),
        }

    def get_lego_config_json(self) -> str:
        return json.dumps(self.get_lego_config(), indent=2)


class InstantSubdomainCreatedInfo:
    PARENT_DOMAIN = "localhostcert.net."

    def __init__(self, username: str, password: str, subdomain: str):
        self.username = username
        self.password = password
        self.subdomain = subdomain

    def get_fulldomain(self) -> str:
        return f"{self.subdomain}.{InstantSubdomainCreatedInfo.PARENT_DOMAIN}"

    def get_credentials(self):
        return Credentials(
            self.username, self.password, self.subdomain, self.get_fulldomain()
        )


def create_instant_subdomain(is_delegate: bool) -> InstantSubdomainCreatedInfo:
    subdomain_name = str(uuid.uuid4())
    parent_name = InstantSubdomainCreatedInfo.PARENT_DOMAIN
    new_fqdn = f"{subdomain_name}.{parent_name}"
    logging.info(f"Creating instant domain {new_fqdn} for anonymous user")

    new_zone = Zone.objects.create(
        name=new_fqdn,
        owner=None,
        is_delegate=is_delegate,
    )
    zone_key, secret = ZoneApiKey.create(new_zone)

    return InstantSubdomainCreatedInfo(
        subdomain=subdomain_name,
        username=str(zone_key.id),
        password=secret,
    )


class AddResult(Enum):
    ADDED = 1
    NOT_ADDED_ALREADY_EXISTS = 2
    NOT_ADDED_LIMIT_EXCEEDED = 3


def add_acme_challenge_response(
    zone: Zone, txt: str, strategy_rotate: bool, is_delegate: bool
) -> AddResult:
    if is_delegate:
        # Put the challenge on the subdomain directly
        # This is how acme-dns does it and it prevents someone from registering
        # a cert for the delegate subdomain
        rr_name = zone.name
    else:
        rr_name = f"{ACME_CHALLENGE_LABEL}.{zone.name}"
    record, created = ManagedDomainName.objects.get_or_create(
        name=rr_name,
        zone=zone,
    )
    if txt in [record.new_challenge_response, record.old_challenge_response]:
        # Already present
        return AddResult.NOT_ADDED_ALREADY_EXISTS

    if (
        record.old_challenge_response
        and record.new_challenge_response
        and not strategy_rotate
    ):
        # Both are set and we aren't rotating: limit exceeded
        return AddResult.NOT_ADDED_LIMIT_EXCEEDED
    else:
        # Rotate in the new response
        record.old_challenge_response = record.new_challenge_response
        record.new_challenge_response = txt
        record.save()
        return AddResult.ADDED


def delete_acme_challenge_record(zone: Zone, txt: str) -> bool:
    if zone.is_delegate:
        rr_name = zone.name
    else:
        rr_name = f"{ACME_CHALLENGE_LABEL}.{zone.name}"

    try:
        managed = ManagedDomainName.objects.get(name=rr_name)
    except ManagedDomainName.DoesNotExist:
        return False

    records = [managed.new_challenge_response, managed.old_challenge_response]
    updated_records = [_ for _ in records if _ != txt]
    if len(records) == len(updated_records):
        # Nothing removed
        return False
    elif len(updated_records) == 1:
        # One item removed
        managed.old_challenge_response = ""
        managed.new_challenge_response = updated_records[0]
        managed.save()
        return True
    else:
        # No records remain
        managed.delete()
        return True
