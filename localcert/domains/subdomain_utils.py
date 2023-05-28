import logging
import uuid

from django.conf import settings
from typing import Dict

from .constants import (
    API_ENDPOINT_BASE,
    DEFAULT_DKIM_POLICY,
    DEFAULT_DMARC_POLICY,
    DEFAULT_MX_RECORD,
    DEFAULT_SPF_POLICY,
)
from .models import Zone, ZoneApiKey
from .pdns import pdns_create_zone, pdns_replace_rrset
from .utils import remove_trailing_dot


class InstantSubdomainCreatedInfo:
    PARENT_DOMAIN = "localhostcert.net."

    def __init__(self, username, password, subdomain):
        self.username = username
        self.password = password
        self.subdomain = subdomain

    def get_fulldomain(self) -> str:
        return f"{self.subdomain}.{InstantSubdomainCreatedInfo.PARENT_DOMAIN}"

    def get_config(self) -> Dict[str, str]:
        return {
            "username": self.username,
            "password": self.password,
            "fulldomain": remove_trailing_dot(self.get_fulldomain()),
            "subdomain": self.subdomain,
            # See: https://github.com/joohoi/acme-dns/issues/341
            "server_url": API_ENDPOINT_BASE,
            "allowfrom": [],
        }


def create_instant_subdomain(is_delegate: bool) -> InstantSubdomainCreatedInfo:
    subdomain_name = str(uuid.uuid4())
    parent_name = InstantSubdomainCreatedInfo.PARENT_DOMAIN
    new_fqdn = f"{subdomain_name}.{parent_name}"

    logging.info(f"Creating instant domain {new_fqdn} for anonymous user")
    set_up_pdns_for_zone(new_fqdn, parent_name)

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


def set_up_pdns_for_zone(zone_name: str, parent_zone: str):
    assert zone_name.endswith("." + parent_zone)

    pdns_create_zone(zone_name)

    # localhostcert.net has predefined A records locked to localhost
    if parent_zone == "localhostcert.net.":
        pdns_replace_rrset(zone_name, zone_name, "A", 86400, ["127.0.0.1"])
    else:
        # Others don't have default A records
        assert parent_zone == "localcert.net."

    pdns_replace_rrset(zone_name, zone_name, "TXT", 1, [DEFAULT_SPF_POLICY])
    pdns_replace_rrset(
        zone_name, f"_dmarc.{zone_name}", "TXT", 86400, [DEFAULT_DMARC_POLICY]
    )
    pdns_replace_rrset(
        zone_name, f"*._domainkey.{zone_name}", "TXT", 86400, [DEFAULT_DKIM_POLICY]
    )
    pdns_replace_rrset(zone_name, zone_name, "MX", 86400, [DEFAULT_MX_RECORD])

    pdns_replace_rrset(
        zone_name,
        zone_name,
        "NS",
        60,
        [
            settings.LOCALCERT_PDNS_NS1,
            settings.LOCALCERT_PDNS_NS2,
        ],
    )

    pdns_replace_rrset(
        zone_name,
        zone_name,
        "SOA",
        60,
        [
            settings.LOCALCERT_PDNS_NS1
            + " soa-admin.robalexdev.com. 0 10800 3600 604800 3600",
        ],
    )

    # Delegation from parent zone
    pdns_replace_rrset(
        parent_zone,
        zone_name,
        "NS",
        60,
        [
            settings.LOCALCERT_PDNS_NS1,
            settings.LOCALCERT_PDNS_NS2,
        ],
    )
