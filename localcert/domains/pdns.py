import requests

from .utils import CustomExceptionServerError
from django.conf import settings


PDNS_API_BASE_URL = f"http://{settings.LOCALCERT_PDNS_SERVER_IP}:{settings.LOCALCERT_PDNS_API_PORT}/api/v1"
PDNS_HEADERS = {
    "X-API-Key": settings.LOCALCERT_PDNS_API_KEY,
    "accept": "application/json",
}


def pdns_create_zone(zone: str):
    assert zone.endswith(".")
    # Create zone in pdns
    resp = requests.post(
        PDNS_API_BASE_URL + "/servers/localhost/zones",
        headers=PDNS_HEADERS,
        json={
            "name": zone,
            "kind": "Native",
        },
    )
    json_resp = resp.json()

    if "error" in json_resp.keys():
        raise CustomExceptionServerError(json_resp["error"])

    # success
    return


# TODO use the targeted name/type
def pdns_describe_domain(zone_name: str) -> dict:
    assert zone_name.endswith(".")

    # TODO: newer pdns versions can filter by name/type
    resp = requests.get(
        f"{PDNS_API_BASE_URL}/servers/localhost/zones/{zone_name}",
        headers=PDNS_HEADERS,
    )
    if resp.status_code != requests.codes.ok:
        raise CustomExceptionServerError(
            f"Unable to describe domain, PDNS error code: {resp.status_code}"
        )

    return resp.json()


def pdns_delete_rrset(zone_name: str, rr_name: str, rrtype: str):
    assert zone_name.endswith(".")
    assert rr_name.endswith(zone_name)
    assert rrtype == "TXT"

    resp = requests.patch(
        f"{PDNS_API_BASE_URL}/servers/localhost/zones/{zone_name}",
        headers=PDNS_HEADERS,
        json={
            "rrsets": [
                {
                    "name": rr_name,
                    "type": "TXT",
                    "changetype": "DELETE",
                },
            ],
        },
    )

    if resp.status_code != requests.codes.no_content:
        raise CustomExceptionServerError(f"{resp.status_code}")

    # success
    return


def pdns_replace_rrset(zone_name: str, rr_name: str, rr_type: str, ttl: int, records):
    assert rr_name.endswith(".")
    assert rr_name.endswith(zone_name)
    assert rr_type in ["TXT", "A"]

    resp = requests.patch(
        f"{PDNS_API_BASE_URL}/servers/localhost/zones/{zone_name}",
        headers=PDNS_HEADERS,
        json={
            "rrsets": [
                {
                    "name": rr_name,
                    "type": rr_type,
                    "changetype": "REPLACE",
                    "ttl": ttl,
                    "records": records,
                },
            ],
        },
    )

    if resp.status_code != requests.codes.no_content:
        raise CustomExceptionServerError(f"{resp.status_code}")

    # success
    return
