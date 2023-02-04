import logging

from django.http import (
    HttpResponse,
    HttpRequest,
    HttpResponseBadRequest,
    Http404,
)
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.views.decorators.http import require_GET, require_POST

from .utils import validate_acme_dns01_txt_value, ACME_CHALLENGE_LABEL

from .models import (
    Zone,
    DomainNameHelper,
)
from .pdns import (
    pdns_create_zone,
    pdns_replace_rrset,
    pdns_describe_domain,
    pdns_delete_rrset,
)

from .decorators import require_zone_access, use_custom_errors

from django.conf import settings


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
            "domain_limit": settings.LOCALCERT_DOMAIN_LIMIT,
        },
    )


@use_custom_errors
@require_POST
@login_required
def create_free_domain(request: HttpRequest) -> HttpResponse:
    zone_count = Zone.objects.filter(
        owner=request.user,
    ).count()

    if zone_count >= settings.LOCALCERT_DOMAIN_LIMIT:
        return HttpResponseBadRequest("Domain limit already reached")

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
    request: HttpRequest, validated_zone: Zone, zone_name: str
) -> HttpResponse:
    details = pdns_describe_domain(validated_zone.name)

    txt_records = [rrset for rrset in details["rrsets"] if rrset["type"] == "TXT"]
    if len(txt_records) == 0:
        can_add_records = True
    elif len(txt_records) == 1:
        record_count = len(txt_records[0]["records"])
        can_add_records = record_count < settings.LOCALCERT_TXT_RECORDS_PER_RRSET_LIMIT
    else:
        # TODO: eventually support subdomains
        assert False, "Expected only one TXT rrset per domain"

    return render(
        request,
        "domain_detail.html",
        {
            "domain": validated_zone,
            "rrsets": details["rrsets"],
            "can_add_records": can_add_records,
        },
    )


@use_custom_errors
@require_GET
@login_required
@require_zone_access(zonekw="zone_name")
def create_resource_record_page(
    request: HttpRequest, zone_name: str, validated_zone: Zone
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
@login_required
@require_zone_access(zonekw="rr_name", isTXT=True)
def modify_rrset(
    request: HttpRequest, rr_name: str, validated_zone: Zone
) -> HttpResponse:
    try:
        rr_type = request.POST["rr_type"]
        rr_content = request.POST["rr_content"]
        edit_action = request.POST["edit_action"]
    except KeyError as e:
        return HttpResponseBadRequest(
            "Incomplete request: " + str(e) + " " + str(request.POST) + "!"
        )

    # Validate input
    if rr_type == "A":
        return HttpResponse("Unauthorized", status=401)
    elif rr_type != "TXT":
        return HttpResponseBadRequest("Unsupported record type")

    if edit_action not in ["add", "remove"]:
        return HttpResponseBadRequest("Unsupported edit action")

    zone_acme_challenge_rr_name = f"{ACME_CHALLENGE_LABEL}.{validated_zone.name}"
    if rr_name != zone_acme_challenge_rr_name:
        return HttpResponseBadRequest(
            f"Only {zone_acme_challenge_rr_name} can be modified"
        )

    validate_acme_dns01_txt_value(rr_content)

    details = pdns_describe_domain(validated_zone.name)

    # Wrap in quotes
    rr_content = f'"{rr_content}"'

    if details["rrsets"]:
        for rrset in details["rrsets"]:
            if rrset["name"] == rr_name and rrset["type"] == rr_type:
                # found it
                target_rrset = rrset["records"]
                break
        else:
            target_rrset = []
    else:
        target_rrset = []

    if edit_action == "add":
        if len(target_rrset) >= settings.LOCALCERT_TXT_RECORDS_PER_RRSET_LIMIT:
            return HttpResponseBadRequest(
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
        logging.info(
            f"Updating RRSET {rr_name} {rr_type} with {len(target_rrset)} values"
        )
        # Replace to update the content
        pdns_replace_rrset(validated_zone.name, rr_name, rr_type, 10, target_rrset)
    else:
        logging.info(f"Deleting RRSET {rr_name} {rr_type}")
        # Nothing remaining, delete the rr_set
        pdns_delete_rrset(validated_zone.name, rr_name, rr_type)

    return redirect(
        "describe_zone",
        zone_name=validated_zone.name,
    )
