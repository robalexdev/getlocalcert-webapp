import logging

from django.http import (
    Http404,
    HttpRequest,
    HttpResponse,
    JsonResponse,
)
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from .utils import (
    CustomExceptionBadRequest,
    validate_acme_dns01_txt_value,
)

from .constants import (
    ACME_CHALLENGE_LABEL,
    API_KEY_PER_ZONE_LIMIT,
    DOMAIN_PER_USER_LIMIT,
    TXT_RECORDS_PER_RRSET_LIMIT,
)

from .models import (
    Zone,
    ZoneApiKey,
    DomainNameHelper,
)
from .pdns import (
    pdns_create_zone,
    pdns_replace_rrset,
    pdns_describe_domain,
    pdns_delete_rrset,
)

from .decorators import (
    permitted_in_POST,
    require_zone_access,
    use_custom_errors,
    use_custom_json_errors,
    require_api_key,
)


@use_custom_errors
@require_GET
@login_required
def list_zones(request: HttpRequest) -> HttpResponse:
    zones = Zone.objects.filter(owner=request.user,).order_by(
        "name",
    )

    zones = [_ for _ in zones]

    return render(
        request,
        "list_domains.html",
        {
            "zones": zones,
            "domain_limit": DOMAIN_PER_USER_LIMIT,
        },
    )


@use_custom_errors
@require_POST
@permitted_in_POST([])
@login_required
def create_free_domain(
    request: HttpRequest,
) -> HttpResponse:
    zone_count = Zone.objects.filter(
        owner=request.user,
    ).count()

    if zone_count >= DOMAIN_PER_USER_LIMIT:
        raise CustomExceptionBadRequest("Domain limit already reached")

    zone_name = DomainNameHelper.objects.create().get_name() + ".localhostcert.net."

    pdns_create_zone(zone_name)

    # localhostcert.net has predefined A records locked to localhost
    records = [{"content": "127.0.0.1", "disabled": False}]
    pdns_replace_rrset(zone_name, zone_name, "A", 3600, records)

    # Create domain in DB
    # TODO: catch error?
    newZone = Zone.objects.create(
        name=zone_name,
        owner=request.user,
    )

    logging.info(f"Created domain {newZone.name} for user {request.user.id}")

    # TODO success message
    return redirect(
        "describe_zone",
        zone_name=newZone.name,
    )


@use_custom_errors
@require_GET
@login_required
@require_zone_access(zonekw="zone_name")
def describe_zone(
    request: HttpRequest,
    validated_zone: Zone,
    zone_name: str,
) -> HttpResponse:
    keys = ZoneApiKey.objects.filter(
        zone=validated_zone,
    )

    details = pdns_describe_domain(validated_zone.name)

    txt_records = [rrset for rrset in details["rrsets"] if rrset["type"] == "TXT"]
    if len(txt_records) == 0:
        can_add_records = True
    elif len(txt_records) == 1:
        record_count = len(txt_records[0]["records"])
        can_add_records = record_count < TXT_RECORDS_PER_RRSET_LIMIT
    else:
        # TODO: eventually support subdomains
        assert False, "Expected only one TXT rrset per domain"  # pragma: no cover

    return render(
        request,
        "domain_detail.html",
        {
            "domain": validated_zone,
            "keys": keys,
            "can_create_api_key": len(keys) < API_KEY_PER_ZONE_LIMIT,
            "rrsets": details["rrsets"],
            "can_add_records": can_add_records,
        },
    )


@use_custom_errors
@require_GET
@login_required
@require_zone_access(zonekw="zone_name")
def create_resource_record_page(
    request: HttpRequest,
    zone_name: str,
    validated_zone: Zone,
) -> HttpResponse:
    return render(
        request,
        "create_resource_record.html",
        {
            "domain": validated_zone,
        },
    )


@use_custom_errors
@require_POST
@permitted_in_POST([])
@login_required
@require_zone_access(zonekw="zone_name")
def create_zone_api_key(
    request: HttpRequest,
    zone_name: str,
    validated_zone: Zone,
) -> HttpResponse:
    zone_api_key_count = ZoneApiKey.objects.filter(
        zone=validated_zone,
    ).count()

    if zone_api_key_count >= API_KEY_PER_ZONE_LIMIT:
        raise CustomExceptionBadRequest(
            "Cannot create more API keys for zone",
        )

    zoneKey, secret = ZoneApiKey.create(validated_zone)

    return render(
        request,
        "show_new_api_key.html",
        {
            "domain": validated_zone.name,
            "secretKeyId": zoneKey.id,
            "secretKey": secret,
        },
    )


@use_custom_errors
@require_POST
@permitted_in_POST(["secret_key_id"])
@login_required
@require_zone_access(zonekw="zone_name")
def delete_zone_api_key(
    request: HttpRequest,
    zone_name: str,
    validated_zone: Zone,
) -> HttpResponse:
    secretKeyId = request.POST["secret_key_id"]
    zoneKey = ZoneApiKey.objects.get(id=secretKeyId)
    zoneKey.delete()

    # TODO success message
    return redirect(
        "describe_zone",
        zone_name=validated_zone.name,
    )


@require_GET
def acmedns_api_health(
    request: HttpRequest,
) -> JsonResponse:
    return JsonResponse({})


# An extra API we've added to help check API keys
@use_custom_json_errors
@require_GET
@require_api_key
def acmedns_api_extra_check(
    request: HttpRequest,
    authenticated_key: ZoneApiKey,
) -> JsonResponse:
    return JsonResponse(
        {
            "status": "ok",
            "domain": authenticated_key.zone.name,
        }
    )


# Refer to:
# https://github.com/joohoi/acme-dns/blob/835fbb9ef6cb918f7066b1b644c5e8e6a25608fc/api.go#L102
@use_custom_json_errors
@require_POST
@permitted_in_POST(["subdomain", "txt"], allow_unexpected=True)
@csrf_exempt
@require_api_key
def acmedns_api_update(
    request: HttpRequest,
    authenticated_key: ZoneApiKey,
) -> JsonResponse:
    subdomain = request.POST["subdomain"]
    txt = request.POST["txt"]
    zone = authenticated_key.zone

    if zone.name != f"{subdomain}.localhostcert.net.":
        raise CustomExceptionBadRequest("Cannot set records for chosen subdomain")

    update_txt_record_helper(
        zone_name=zone.name,
        rr_name=f"{ACME_CHALLENGE_LABEL}.{zone.name}",
        edit_action="add",
        rr_content=txt,
        replace_oldest=True,
    )

    return JsonResponse({"txt": txt})


@use_custom_errors
@require_POST
@permitted_in_POST(["rr_type", "rr_content", "edit_action"])
@login_required
@require_zone_access(zonekw="rr_name", isTXT=True)
def modify_rrset(
    request: HttpRequest,
    rr_name: str,
    validated_zone: Zone,
) -> HttpResponse:
    rr_type = request.POST["rr_type"]
    rr_content = request.POST["rr_content"]
    edit_action = request.POST["edit_action"]

    # Validate input
    if rr_type != "TXT":
        raise CustomExceptionBadRequest("Unsupported record type")

    if edit_action not in ["add", "remove"]:
        raise CustomExceptionBadRequest("Unsupported edit action")

    zone_acme_challenge_rr_name = f"{ACME_CHALLENGE_LABEL}.{validated_zone.name}"
    if rr_name != zone_acme_challenge_rr_name:
        raise CustomExceptionBadRequest(
            f"Only {zone_acme_challenge_rr_name} can be modified"
        )

    update_txt_record_helper(
        zone_name=validated_zone.name,
        rr_name=rr_name,
        edit_action=edit_action,
        rr_content=rr_content,
        replace_oldest=False,
    )

    return redirect(
        "describe_zone",
        zone_name=validated_zone.name,
    )


def update_txt_record_helper(
    zone_name: str,
    rr_name: str,
    edit_action: str,
    rr_content: str,
    replace_oldest: bool = False,
):
    validate_acme_dns01_txt_value(rr_content)

    details = pdns_describe_domain(zone_name)

    # Wrap in quotes
    rr_content = f'"{rr_content}"'

    if details["rrsets"]:
        for rrset in details["rrsets"]:
            if rrset["name"] == rr_name and rrset["type"] == "TXT":
                # found it
                target_rrset = rrset["records"]
                break
        else:
            target_rrset = []
    else:
        target_rrset = []

    if edit_action == "add":
        # TODO: limit should be one, to match ACME-DNS
        if len(target_rrset) >= TXT_RECORDS_PER_RRSET_LIMIT:
            if replace_oldest:
                # TODO: This does NOT work. Need to track better
                target_rrset = target_rrset[0:-1]
            else:
                raise CustomExceptionBadRequest(
                    "Limit exceeded, unable to add additional TXT records. Try deleting unneeded records."
                )
        target_rrset.append(
            {
                "content": rr_content,
                "disabled": False,
            }
        )
    else:
        assert edit_action == "remove"
        sz = len(target_rrset)
        target_rrset = [item for item in target_rrset if item["content"] != rr_content]
        if len(target_rrset) == sz:
            # TODO: This should 301 redirect with a warning message that nothing was removed
            raise Http404("Item to remove was not found")

    if target_rrset:
        logging.info(f"Updating RRSET {rr_name} TXT with {len(target_rrset)} values")
        # Replace to update the content
        pdns_replace_rrset(zone_name, rr_name, "TXT", 10, target_rrset)
    else:
        logging.info(f"Deleting RRSET {rr_name} TXT")
        # Nothing remaining, delete the rr_set
        pdns_delete_rrset(zone_name, rr_name, "TXT")
