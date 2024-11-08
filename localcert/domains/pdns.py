import requests
import logging

from .utils import CustomExceptionServerError
from datetime import datetime
from django.conf import settings
from typing import List


PDNS_API_BASE_URL = f"http://{settings.LOCALCERT_PDNS_SERVER_IP}:{settings.LOCALCERT_PDNS_API_PORT}/api/v1"
PDNS_HEADERS = {
    "X-API-Key": settings.LOCALCERT_PDNS_API_KEY,
    "accept": "application/json",
}


def pdns_create_zone(zone: str):
    assert zone.endswith(".")

    logging.debug(f"[PDNS] Create {zone}")

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
        raise CustomExceptionServerError(json_resp["error"])  # pragma: no cover

    # success
    return


# TODO use the targeted name/type
def pdns_describe_domain(zone_name: str) -> dict:
    assert zone_name.endswith(".")

    logging.debug(f"[PDNS] Describe {zone_name}")

    # TODO: newer pdns versions can filter by name/type
    resp = requests.get(
        f"{PDNS_API_BASE_URL}/servers/localhost/zones/{zone_name}",
        headers=PDNS_HEADERS,
    )
    if resp.status_code != requests.codes.ok:
        raise CustomExceptionServerError(
            f"Unable to describe domain, PDNS error code: {resp.status_code}"
        )  # pragma: no cover

    return resp.json()


def pdns_delete_rrset(zone_name: str, rr_name: str, rrtype: str):
    assert zone_name.endswith(".")
    assert rr_name.endswith(zone_name)
    assert rrtype == "TXT"

    logging.debug(f"[PDNS] Delete {zone_name} {rr_name} {rrtype}")

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
        raise CustomExceptionServerError(f"{resp.status_code}")  # pragma: no cover

    # success
    return


def pdns_replace_rrset(
    zone_name: str, rr_name: str, rr_type: str, ttl: int, record_contents: List[str]
):
    """

    record_contents - Records from least recently added
    """
    assert rr_name.endswith(".")
    assert rr_name.endswith(zone_name)
    assert rr_type in ["TXT", "A", "MX", "NS", "SOA"]

    logging.debug(
        f"[PDNS] Replace {zone_name} {rr_name} {rr_type} {ttl} {record_contents}"
    )

    records = [
        {
            "content": content,
            "disabled": False,
        }
        for content in record_contents
    ]
    comments = [
        {
            "content": f"{record_contents[idx]} : {idx}",
            "account": "",
            "modified_at": int(datetime.now().timestamp()),
        }
        for idx in range(len(record_contents))
    ]

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
                    "comments": comments,
                },
            ],
        },
    )

    if resp.status_code != requests.codes.no_content:
        raise CustomExceptionServerError(
            f"{resp.status_code}: {resp.content.decode('utf-8')}"
        )  # pragma: no cover

    # success
    return


def pdns_get_stats():
    resp = requests.get(
        f"{PDNS_API_BASE_URL}/servers/localhost/statistics",
        headers=PDNS_HEADERS,
    )

    if resp.status_code != 200:  # pragma: no cover
        logging.error(f"{resp.status_code}: {resp.content.decode('utf-8')}")
        return {}

    # success
    return resp.json()
