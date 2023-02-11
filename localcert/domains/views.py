import logging

from .constants import (
    ACME_CHALLENGE_LABEL,
    API_KEY_PER_ZONE_LIMIT,
    DOMAIN_PER_USER_LIMIT,
    TXT_RECORDS_PER_RRSET_LIMIT,
)
from .decorators import (
    require_api_key,
    use_custom_errors,
    use_custom_json_errors,
)
from .models import (
    Zone,
    ZoneApiKey,
    DomainNameHelper,
)
from .pdns import (
    pdns_create_zone,
    pdns_delete_rrset,
    pdns_describe_domain,
    pdns_replace_rrset,
)
from .utils import (
    CustomExceptionBadRequest,
    build_url,
)
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.http import (
    Http404,
    HttpRequest,
    HttpResponse,
    JsonResponse,
)
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from domains.forms import (
    AcmeDnsUpdateRecordForm,
    AddRecordForm,
    CreateZoneApiKeyForm,
    DeleteRecordForm,
    DeleteZoneApiKeyForm,
    DescribeZoneForm,
)
from enum import Enum


@use_custom_errors
@require_GET
@login_required
def list_zones(request: HttpRequest) -> HttpResponse:
    zones = Zone.objects.filter(owner=request.user,).order_by(
        "name",
    )

    zones = [
        {
            "name": zone.name,
            "url": build_url(describe_zone, params={"zone_name": zone.name}),
        }
        for zone in zones
    ]

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
    newZone = Zone.objects.create(
        name=zone_name,
        owner=request.user,
    )

    logging.info(f"Created domain {newZone.name} for user {request.user.id}")

    # TODO success message
    return redirect(
        build_url(
            "describe_zone",
            params={
                "zone_name": newZone.name,
            },
        )
    )


@use_custom_errors
@require_GET
@login_required
def describe_zone(
    request: HttpRequest,
) -> HttpResponse:
    form = DescribeZoneForm(request.GET)
    if not form.is_valid():
        raise CustomExceptionBadRequest(
            ". ".join(
                [k + ": " + " ".join(x for x in v) for k, v in form.errors.items()]
            )
        )
    zone_name = form.cleaned_data["zone_name"]

    zone = (
        Zone.objects.prefetch_related("zoneapikey_set")
        .filter(
            name=zone_name,
            owner=request.user,
        )
        .first()
    )
    if not zone:
        raise CustomExceptionBadRequest(
            "Domain does not exist, or you are not the owner",
            status_code=404,
        )

    keys = [_ for _ in zone.zoneapikey_set.all()]

    details = pdns_describe_domain(zone.name)

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
            "domain": zone,
            "create_resource_record_url": build_url(
                add_record, params={"zone_name": zone.name}
            ),
            "keys": keys,
            "can_create_api_key": len(keys) < API_KEY_PER_ZONE_LIMIT,
            "rrsets": details["rrsets"],
            "can_add_records": can_add_records,
        },
    )


@use_custom_errors
@require_POST
@login_required
def create_zone_api_key(
    request: HttpRequest,
) -> HttpResponse:
    form = CreateZoneApiKeyForm(request.POST)
    if not form.is_valid():
        raise CustomExceptionBadRequest(
            ". ".join(
                [k + ": " + " ".join(x for x in v) for k, v in form.errors.items()]
            )
        )
    zone_name = form.cleaned_data["zone_name"]

    zone = (
        Zone.objects.annotate(Count("zoneapikey"))
        .filter(
            name=zone_name,
            owner=request.user,
        )
        .first()
    )
    if not zone:
        raise CustomExceptionBadRequest(
            "Domain does not exist, or you are not the owner",
            status_code=404,
        )

    if zone.zoneapikey__count >= API_KEY_PER_ZONE_LIMIT:
        raise CustomExceptionBadRequest(
            "Cannot create more API keys for zone",
        )

    zoneKey, secret = ZoneApiKey.create(zone)

    return render(
        request,
        "show_new_api_key.html",
        {
            "domain": zone.name,
            "describe_zone_url": build_url(
                describe_zone, params={"zone_name": zone.name}
            ),
            "secretKeyId": zoneKey.id,
            "secretKey": secret,
        },
    )


@use_custom_errors
@require_POST
@login_required
def delete_zone_api_key(
    request: HttpRequest,
) -> HttpResponse:
    form = DeleteZoneApiKeyForm(request.POST)
    if not form.is_valid():
        raise CustomExceptionBadRequest(
            ". ".join(
                [k + ": " + " ".join(x for x in v) for k, v in form.errors.items()]
            )
        )

    secretKeyId = form.cleaned_data["secret_key_id"]
    zoneKey = ZoneApiKey.objects.filter(id=secretKeyId).first()

    if not zoneKey or zoneKey.zone.owner != request.user:
        raise CustomExceptionBadRequest(
            "API Key does not exist, or you are not the owner", status_code=404
        )

    zoneKey.delete()

    # TODO success message
    return redirect(
        build_url(
            "describe_zone",
            params={"zone_name": zoneKey.zone.name},
        )
    )


@require_GET
def acmedns_api_health(
    request: HttpRequest,
) -> JsonResponse:
    return JsonResponse({})


# An extra API we've added to help check API keys
# TODO move this out of acme-dns namespace, it's not part of that...
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
@csrf_exempt
@require_api_key
def acmedns_api_update(
    request: HttpRequest,
    authenticated_key: ZoneApiKey,
) -> JsonResponse:
    form = AcmeDnsUpdateRecordForm(request.POST)
    if not form.is_valid():
        raise CustomExceptionBadRequest(
            ". ".join(
                [k + ": " + " ".join(x for x in v) for k, v in form.errors.items()]
            )
        )

    subdomain = form.cleaned_data["subdomain"]
    txt = form.cleaned_data["txt"]
    zone = authenticated_key.zone

    if zone.name != f"{subdomain}.localhostcert.net.":
        raise CustomExceptionBadRequest(
            "Subdomain does not exist or the provided key does not have access",
            status_code=404,
        )

    update_txt_record_helper(
        zone_name=zone.name,
        rr_name=f"{ACME_CHALLENGE_LABEL}.{zone.name}",
        edit_action=EditActionEnum.ADD,
        rr_content=txt,
        replace_oldest=True,
    )

    return JsonResponse({"txt": txt})


@use_custom_errors
@require_http_methods(["GET", "POST"])
@login_required
def delete_record(
    request: HttpRequest,
) -> HttpResponse:
    if request.method == "POST":
        form = DeleteRecordForm(request.POST)
        if not form.is_valid():
            return render(
                request, "delete_resource_record.html", {"form": form}, status=400
            )
        zone_name: str = form.cleaned_data["zone_name"]
        rr_content: str = form.cleaned_data["rr_content"]

        zone = Zone.objects.filter(
            name=zone_name,
            owner=request.user,
        ).first()
        if not zone:
            raise CustomExceptionBadRequest(
                "Domain does not exist, or you are not the owner",
                status_code=404,
            )

        rr_name = f"{ACME_CHALLENGE_LABEL}.{zone.name}"
        update_txt_record_helper(
            zone_name=zone.name,
            rr_name=rr_name,
            edit_action=EditActionEnum.REMOVE,
            rr_content=rr_content,
            replace_oldest=False,
        )

        return redirect(
            build_url(
                "describe_zone",
                params={"zone_name": zone.name},
            )
        )

    assert request.method == "GET"
    form = DeleteRecordForm(
        initial=request.GET,
    )
    return render(request, "delete_resource_record.html", {"form": form})


@use_custom_errors
@require_http_methods(["GET", "POST"])
@login_required
def add_record(
    request: HttpRequest,
) -> HttpResponse:
    if request.method == "POST":
        form = AddRecordForm(request.POST)
        if not form.is_valid():
            return render(
                request, "create_resource_record.html", {"form": form}, status=400
            )

        zone_name: str = form.cleaned_data["zone_name"]
        rr_content: str = form.cleaned_data["rr_content"]

        zone = Zone.objects.filter(
            name=zone_name,
            owner=request.user,
        ).first()
        if not zone:
            raise CustomExceptionBadRequest(
                "Domain does not exist, or you are not the owner",
                status_code=404,
            )

        rr_name = f"{ACME_CHALLENGE_LABEL}.{zone.name}"
        update_txt_record_helper(
            zone_name=zone.name,
            rr_name=rr_name,
            edit_action=EditActionEnum.ADD,
            rr_content=rr_content,
            replace_oldest=False,
        )

        return redirect(
            build_url(
                "describe_zone",
                params={"zone_name": zone.name},
            )
        )

    assert request.method == "GET"
    form = AddRecordForm(
        initial=request.GET,
    )
    return render(request, "create_resource_record.html", {"form": form})


class EditActionEnum(Enum):
    ADD = 1
    REMOVE = 2


def update_txt_record_helper(
    zone_name: str,
    rr_name: str,
    edit_action: EditActionEnum,
    rr_content: str,
    replace_oldest: bool = False,
):
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

    if edit_action == EditActionEnum.ADD:
        if any([rr_content == existing["content"] for existing in target_rrset]):
            logging.debug("Adding a duplicated, no action needed")
            return

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
        assert edit_action == EditActionEnum.REMOVE
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
