import datetime
import json
import logging

from django.urls import reverse
from django.utils import timezone
from requests.structures import CaseInsensitiveDict

from .subdomain_utils import Credentials, create_instant_subdomain, set_up_pdns_for_zone
from .validators import validate_acme_dns01_txt_value, validate_label

from .constants import (
    ACME_CHALLENGE_LABEL,
    API_KEY_PER_ZONE_LIMIT,
    DEFAULT_SPF_POLICY,
    TXT_RECORDS_PER_RRSET_LIMIT,
)
from .decorators import (
    require_api_key,
    require_hostname,
    use_custom_errors,
    use_custom_json_errors,
)
from .models import (
    User,
    Zone,
    ZoneApiKey,
)
from .pdns import (
    pdns_delete_rrset,
    pdns_describe_domain,
    pdns_replace_rrset,
)
from .rate_limit import (
    should_delegate_domain_creation_throttle,
    should_instant_domain_creation_throttle,
)
from .utils import (
    CustomExceptionBadRequest,
    domain_limit_for_user,
    sort_records_key,
    build_url,
)
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from django.http import (
    HttpRequest,
    HttpResponse,
    JsonResponse,
)
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST, require_http_methods
from domains.forms import (
    AddRecordForm,
    CreateZoneApiKeyForm,
    RegisterInstantSubdomainForm,
    RegisterSubdomain,
    DeleteRecordForm,
    DeleteZoneApiKeyForm,
    DescribeZoneForm,
)
from enum import Enum
from http import HTTPStatus
from typing import List


@require_GET
def home_page(request: HttpRequest) -> HttpResponse:
    return render(
        request,
        "home.html",
        {"enable_instant_domains": not should_instant_domain_creation_throttle()},
    )


@require_GET
def login_page(request: HttpRequest) -> HttpResponse:
    return render(
        request,
        "login.html",
    )


@use_custom_errors
@require_GET
@login_required
def list_zones(request: HttpRequest) -> HttpResponse:
    zones = Zone.objects.filter(
        owner=request.user,
    ).order_by(
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
            "domain_limit": domain_limit_for_user(request.user),
        },
    )


@use_custom_errors
@require_http_methods(["GET", "POST"])
@login_required
def register_subdomain(
    request: HttpRequest,
) -> HttpResponse:
    form_status = HTTPStatus.OK

    # Make sure the user is within limits
    zone_count = Zone.objects.filter(
        owner=request.user,
    ).count()
    if zone_count >= domain_limit_for_user(request.user):
        messages.warning(request, "Subdomain limit reached")
        return redirect(reverse(list_zones))

    if request.method == "POST":
        form = RegisterSubdomain(request.POST)
        if not form.is_valid():
            form_status = HTTPStatus.BAD_REQUEST
        else:
            parent_zone = form.cleaned_data["parent_zone"]
            zone_name = form.cleaned_data["zone_name"]  # synthetic field

            logging.info(f"Creating domain {zone_name} for user {request.user.id}...")
            set_up_pdns_for_zone(zone_name, parent_zone)
            newZone = Zone.objects.create(
                name=zone_name,
                owner=request.user,
            )
            logging.info(f"Created domain {newZone.name} for user {request.user.id}")

            messages.success(request, f"Created {newZone.name}")
            return redirect(
                build_url(
                    "describe_zone",
                    params={
                        "zone_name": newZone.name,
                    },
                )
            )
    else:
        form = RegisterSubdomain()
    return render(request, "create_subdomain.html", {"form": form}, status=form_status)


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
            "Subdomain does not exist, or you are not the owner",
            status_code=404,
        )

    keys = [_ for _ in zone.zoneapikey_set.all()]

    details = pdns_describe_domain(zone.name)
    records = sorted(details["rrsets"], key=sort_records_key)

    zone_txt_records = [
        rrset
        for rrset in details["rrsets"]
        if rrset["type"] == "TXT"
        and rrset["name"] == f"{ACME_CHALLENGE_LABEL}.{zone.name}"
    ]
    if len(zone_txt_records) == 0:
        can_add_records = True
    elif len(zone_txt_records) == 1:
        record_count = len(zone_txt_records[0]["records"])
        can_add_records = record_count < TXT_RECORDS_PER_RRSET_LIMIT
    else:
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
            "rrsets": records,
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
            "Subdomain does not exist, or you are not the owner",
            status_code=404,
        )
    if zone.zoneapikey__count >= API_KEY_PER_ZONE_LIMIT:
        raise CustomExceptionBadRequest(
            "Cannot create more API keys for zone",
        )

    zoneKey, secret = ZoneApiKey.create(zone)
    logging.info(f"API Key created for {request.user} {zone.name}: {zoneKey.id}")

    credentialInfo = Credentials(
        username=str(zoneKey.id),
        password=secret,
        subdomain=zone.get_subdomain_name(),
        fulldomain=zone.name,
    )

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
            "credentials_json": credentialInfo.get_config_json(),
            "credentials_lego_json": credentialInfo.get_lego_config_json(),
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
    zone_name = zoneKey.zone.name

    if not zoneKey or zoneKey.zone.owner != request.user:
        raise CustomExceptionBadRequest(
            "API Key does not exist, or you are not the owner", status_code=404
        )

    zoneKey.delete()

    logging.info(f"API Key deleted for {request.user} {zone_name}: {zoneKey.id}")
    messages.success(request, "API Key deleted")

    return redirect(
        build_url(
            "describe_zone",
            params={"zone_name": zone_name},
        )
    )


@require_POST
def instant_subdomain(
    request: HttpRequest,
) -> HttpResponse:
    if should_instant_domain_creation_throttle():
        logging.warning("Throttled!")
        messages.warning(
            request,
            "Too many instant domains have been created recently. Try again later.",
        )
        return redirect(login_page)

    # TODO expiration
    created = create_instant_subdomain(is_delegate=False)
    return render(
        request,
        "instant_subdomain.html",
        {
            "username": created.username,
            "password": created.password,
            "fulldomain": created.get_fulldomain(),
            "credentials_json": created.get_credentials().get_config_json(),
            "credentials_lego_json": created.get_credentials().get_lego_config_json(),
        },
        status=HTTPStatus.CREATED,
    )


@require_POST
@csrf_exempt
def api_instant_subdomain(
    request: HttpRequest,
) -> HttpResponse:
    form = RegisterInstantSubdomainForm(request.POST)
    if not form.is_valid():
        return JsonResponse(
            {"error": "invalid request"},
            status=HTTPStatus.BAD_REQUEST,
        )

    if should_instant_domain_creation_throttle():
        logging.warning("Throttled!")
        return JsonResponse(
            {"error": "Throttled"},
            status=420,
        )

    created = create_instant_subdomain(is_delegate=False)
    if form.cleaned_data["output_format"] == "lego":
        config_blob = created.get_credentials().get_lego_config()
    else:
        config_blob = created.get_credentials().get_config()

    # TODO expiration
    return JsonResponse(
        config_blob,
        status=HTTPStatus.CREATED,
    )


# API to check health
# Used by load balancer
@require_GET
def api_health(
    _: HttpRequest,
) -> JsonResponse:
    return JsonResponse({"healthy": True})


# acme-dns compat API to check health
@use_custom_json_errors
@require_GET
@require_hostname("api.getlocalcert.net")
def acmedns_api_health(
    _: HttpRequest,
) -> HttpResponse:
    # ACME DNS just returns 200 OK with no content
    # https://github.com/joohoi/acme-dns/blob/master/api.go#L111
    return HttpResponse("")


# API to check API keys
@use_custom_json_errors
@require_GET
@require_hostname("api.getlocalcert.net")
@require_api_key
def api_check_key(
    _: HttpRequest,
    authenticated_key: ZoneApiKey,
) -> JsonResponse:
    return JsonResponse(
        {
            "status": "ok",
            "domain": authenticated_key.zone.name,
        }
    )


# API to register an anonymous zone
@use_custom_json_errors
@require_POST
@csrf_exempt
@require_hostname("api.getlocalcert.net")
def acmedns_api_register(
    _: HttpRequest,
) -> JsonResponse:
    if should_delegate_domain_creation_throttle():
        logging.warning("Throttled!")
        return JsonResponse(
            {"error": "Throttled"},
            status=420,
        )

    # TODO: support allowfrom
    created = create_instant_subdomain(is_delegate=True)
    return JsonResponse(
        created.get_credentials().get_config(),
        status=HTTPStatus.CREATED,
    )


# Refer to:
# https://github.com/joohoi/acme-dns/blob/835fbb9ef6cb918f7066b1b644c5e8e6a25608fc/api.go#L102
@use_custom_json_errors
@require_POST
@csrf_exempt
@require_hostname("api.getlocalcert.net")
@require_api_key
def acmedns_api_update(
    request: HttpRequest,
    authenticated_key: ZoneApiKey,
) -> JsonResponse:
    body = json.loads(request.body.decode("utf-8"))
    body = CaseInsensitiveDict(body)

    try:
        subdomain = body["subdomain"]
        validate_label(ban_words=False, label=subdomain)
    except KeyError:
        raise CustomExceptionBadRequest("subdomain: This field is required")

    try:
        txt = body["txt"]
        validate_acme_dns01_txt_value(txt)
    except KeyError:
        raise CustomExceptionBadRequest("txt: This field is required")

    zone: Zone = authenticated_key.zone

    if (
        zone.name != f"{subdomain}.localhostcert.net."
        and zone.name != f"{subdomain}.localcert.net."
    ):
        raise CustomExceptionBadRequest(
            "Subdomain does not exist or the provided key does not have access",
            status_code=404,
        )

    if zone.is_delegate:
        # Put the challenge on the subdomain directly
        # This is how acme-dns does it and it prevents someone from registering
        # a cert for the delegate subdomain
        rr_name = zone.name
    else:
        rr_name = f"{ACME_CHALLENGE_LABEL}.{zone.name}"

    update_txt_record_helper(
        request=request,
        zone_name=zone.name,
        rr_name=rr_name,
        edit_action=EditActionEnum.ADD,
        rr_content=txt,
        is_web_request=False,
    )

    return JsonResponse({"txt": txt})


@use_custom_errors
@require_http_methods(["GET", "POST"])
@login_required
def delete_record(
    request: HttpRequest,
) -> HttpResponse:
    form_status = HTTPStatus.OK
    if request.method == "POST":
        form = DeleteRecordForm(request.POST)
        if not form.is_valid():
            form_status = HTTPStatus.BAD_REQUEST
        else:
            zone_name: str = form.cleaned_data["zone_name"]
            rr_content: str = form.cleaned_data["rr_content"]

            zone = Zone.objects.filter(
                name=zone_name,
                owner=request.user,
            ).first()
            if not zone:
                raise CustomExceptionBadRequest(
                    "Subdomain does not exist, or you are not the owner",
                    status_code=404,
                )

            rr_name = f"{ACME_CHALLENGE_LABEL}.{zone.name}"
            update_txt_record_helper(
                request=request,
                zone_name=zone.name,
                rr_name=rr_name,
                edit_action=EditActionEnum.REMOVE,
                rr_content=rr_content,
                is_web_request=True,
            )

            return redirect(
                build_url(
                    "describe_zone",
                    params={"zone_name": zone.name},
                )
            )
    else:
        assert request.method == "GET"
        form = DeleteRecordForm(
            initial=request.GET,
        )
    return render(
        request, "delete_resource_record.html", {"form": form}, status=form_status
    )


@require_GET
def show_stats(
    request: HttpRequest,
) -> HttpResponse:
    # Access control
    if request.user.username != "robalexdev":
        return HttpResponse("Not found", status=404)

    now = timezone.now()
    one_day_ago = now - datetime.timedelta(days=1)
    one_week_ago = now - datetime.timedelta(days=7)
    thirty_days_ago = now - datetime.timedelta(days=30)
    ninety_days_ago = now - datetime.timedelta(days=90)

    last_created_user = User.objects.order_by("date_joined").last()
    last_login_user = User.objects.order_by("last_login").last()
    last_owned_zone_created = (
        Zone.objects.filter(owner__isnull=False).order_by("created").last()
    )
    last_owned_zone_updated = (
        Zone.objects.filter(owner__isnull=False).order_by("updated").last()
    )
    last_anon_zone_created = (
        Zone.objects.filter(owner__isnull=True, is_delegate=False)
        .order_by("created")
        .last()
    )
    last_anon_zone_updated = (
        Zone.objects.filter(owner__isnull=True, is_delegate=False)
        .order_by("updated")
        .last()
    )
    last_delegate_zone_created = (
        Zone.objects.filter(owner__isnull=True, is_delegate=True)
        .order_by("created")
        .last()
    )
    last_delegate_zone_updated = (
        Zone.objects.filter(owner__isnull=True, is_delegate=True)
        .order_by("updated")
        .last()
    )
    last_api_key_created = ZoneApiKey.objects.order_by("created").last()
    last_api_key_used = ZoneApiKey.objects.order_by("last_used").last()

    stats = []

    stats.append(["Newest Users"])
    for user in User.objects.order_by("date_joined")[:10:-1]:
        stats.append(
            [
                user.id,
                user.username,
                user.email,
                user.date_joined,
                user.last_login,
            ]
        )

    stats.append(["Recent Users"])
    for user in User.objects.order_by("last_login")[:10:-1]:
        stats.append(
            [
                user.id,
                user.username,
                user.email,
                user.date_joined,
                user.last_login,
            ]
        )

    stats.append(["Users"])
    stats.append(
        [
            "- created",
            User.objects.filter(date_joined__gt=one_day_ago).count(),
            User.objects.filter(date_joined__gt=one_week_ago).count(),
            User.objects.filter(date_joined__gt=thirty_days_ago).count(),
            User.objects.filter(date_joined__gt=ninety_days_ago).count(),
            User.objects.count(),
            "" if last_created_user is None else last_created_user.date_joined,
        ]
    )
    stats.append(
        [
            "- logged in",
            User.objects.filter(last_login__gt=one_day_ago).count(),
            User.objects.filter(last_login__gt=one_week_ago).count(),
            User.objects.filter(last_login__gt=thirty_days_ago).count(),
            User.objects.filter(last_login__gt=ninety_days_ago).count(),
            "",
            "" if last_login_user is None else last_login_user.last_login,
        ]
    )
    stats.append(
        [
            "- returning users (30 days)",
            User.objects.filter(
                last_login__gt=one_day_ago, date_joined__gt=thirty_days_ago
            ).count(),
            User.objects.filter(
                last_login__gt=one_week_ago, date_joined__gt=thirty_days_ago
            ).count(),
            User.objects.filter(
                last_login__gt=thirty_days_ago, date_joined__gt=thirty_days_ago
            ).count(),
            User.objects.filter(
                last_login__gt=ninety_days_ago, date_joined__gt=thirty_days_ago
            ).count(),
            "",
            "",
        ]
    )

    stats.append(["Newest Zones"])
    for zone in Zone.objects.order_by("created")[:10:-1]:
        stats.append(
            [
                zone.name,
                zone.owner.username,
                zone.created,
                zone.updated,
                zone.is_delegate,
            ]
        )

    stats.append(["Recently Updated Zones"])
    for zone in Zone.objects.order_by("updated")[:10:-1]:
        u = zone.owner.username if zone.owner else "-"
        stats.append(
            [
                zone.name,
                u,
                zone.created,
                zone.updated,
                zone.is_delegate,
            ]
        )

    stats.append(["Recently Updated Zones (older than a month)"])
    for zone in Zone.objects.filter(created__gt=thirty_days_ago).order_by("updated")[
        :10:-1
    ]:
        u = zone.owner.username if zone.owner else "-"
        stats.append(
            [
                zone.name,
                u,
                zone.created,
                zone.updated,
                zone.is_delegate,
            ]
        )

    stats.append(["Zones (owned)"])
    stats.append(
        [
            "- created",
            Zone.objects.filter(created__gt=one_day_ago, owner__isnull=False).count(),
            Zone.objects.filter(created__gt=one_week_ago, owner__isnull=False).count(),
            Zone.objects.filter(
                created__gt=thirty_days_ago, owner__isnull=False
            ).count(),
            Zone.objects.filter(
                created__gt=ninety_days_ago, owner__isnull=False
            ).count(),
            Zone.objects.filter(owner__isnull=False).count(),
            "" if last_owned_zone_created is None else last_owned_zone_created.created,
        ]
    )
    stats.append(
        [
            "- updated",
            Zone.objects.filter(updated__gt=one_day_ago, owner__isnull=False).count(),
            Zone.objects.filter(updated__gt=one_week_ago, owner__isnull=False).count(),
            Zone.objects.filter(
                updated__gt=thirty_days_ago, owner__isnull=False
            ).count(),
            Zone.objects.filter(
                updated__gt=ninety_days_ago, owner__isnull=False
            ).count(),
            "",
            "" if last_owned_zone_updated is None else last_owned_zone_updated.updated,
        ]
    )

    stats.append(["Zones (anonymous)"])
    stats.append(
        [
            "- created",
            Zone.objects.filter(
                created__gt=one_day_ago, owner__isnull=True, is_delegate=False
            ).count(),
            Zone.objects.filter(
                created__gt=one_week_ago, owner__isnull=True, is_delegate=False
            ).count(),
            Zone.objects.filter(
                created__gt=thirty_days_ago, owner__isnull=True, is_delegate=False
            ).count(),
            Zone.objects.filter(
                created__gt=ninety_days_ago, owner__isnull=True, is_delegate=False
            ).count(),
            Zone.objects.filter(owner__isnull=True, is_delegate=False).count(),
            "" if last_anon_zone_created is None else last_anon_zone_created.created,
        ]
    )
    stats.append(
        [
            "- updated",
            Zone.objects.filter(
                updated__gt=one_day_ago, owner__isnull=True, is_delegate=False
            ).count(),
            Zone.objects.filter(
                updated__gt=one_week_ago, owner__isnull=True, is_delegate=False
            ).count(),
            Zone.objects.filter(
                updated__gt=thirty_days_ago, owner__isnull=True, is_delegate=False
            ).count(),
            Zone.objects.filter(
                updated__gt=ninety_days_ago, owner__isnull=True, is_delegate=False
            ).count(),
            "",
            "" if last_anon_zone_updated is None else last_anon_zone_updated.updated,
        ]
    )

    stats.append(["Zones (delegate)"])
    stats.append(
        [
            "- created",
            Zone.objects.filter(
                created__gt=one_day_ago, owner__isnull=True, is_delegate=True
            ).count(),
            Zone.objects.filter(
                created__gt=one_week_ago, owner__isnull=True, is_delegate=True
            ).count(),
            Zone.objects.filter(
                created__gt=thirty_days_ago, owner__isnull=True, is_delegate=True
            ).count(),
            Zone.objects.filter(
                created__gt=ninety_days_ago, owner__isnull=True, is_delegate=True
            ).count(),
            Zone.objects.filter(owner__isnull=True, is_delegate=True).count(),
            ""
            if last_delegate_zone_created is None
            else last_delegate_zone_created.created,
        ]
    )
    stats.append(
        [
            "- updated",
            Zone.objects.filter(
                updated__gt=one_day_ago, owner__isnull=True, is_delegate=True
            ).count(),
            Zone.objects.filter(
                updated__gt=one_week_ago, owner__isnull=True, is_delegate=True
            ).count(),
            Zone.objects.filter(
                updated__gt=thirty_days_ago, owner__isnull=True, is_delegate=True
            ).count(),
            Zone.objects.filter(
                updated__gt=ninety_days_ago, owner__isnull=True, is_delegate=True
            ).count(),
            "",
            ""
            if last_delegate_zone_updated is None
            else last_delegate_zone_updated.updated,
        ]
    )

    stats.append(["Zones (any)"])
    stats.append(
        [
            "- updated in the last 30 days, active since [time]",
            "",
            "",
            Zone.objects.filter(
                updated__lt=thirty_days_ago,
                created__gt=thirty_days_ago,
            ).count(),
            Zone.objects.filter(
                updated__lt=thirty_days_ago,
                created__gt=ninety_days_ago,
            ).count(),
            "",
            "",
        ]
    )

    stats.append(["ZoneApiKey"])
    stats.append(
        [
            "- created",
            ZoneApiKey.objects.filter(created__gt=one_day_ago).count(),
            ZoneApiKey.objects.filter(created__gt=one_week_ago).count(),
            ZoneApiKey.objects.filter(created__gt=thirty_days_ago).count(),
            ZoneApiKey.objects.filter(created__gt=ninety_days_ago).count(),
            ZoneApiKey.objects.count(),
            "" if last_api_key_created is None else last_api_key_created.created,
        ]
    )
    stats.append(
        [
            "- used",
            ZoneApiKey.objects.filter(last_used__gt=one_day_ago).count(),
            ZoneApiKey.objects.filter(last_used__gt=one_week_ago).count(),
            ZoneApiKey.objects.filter(last_used__gt=thirty_days_ago).count(),
            ZoneApiKey.objects.filter(last_used__gt=ninety_days_ago).count(),
            "",
            "" if last_api_key_used is None else last_api_key_used.last_used,
        ]
    )

    return render(
        request,
        "stats.html",
        {"stats": stats},
    )


@use_custom_errors
@require_http_methods(["GET", "POST"])
@login_required
def add_record(
    request: HttpRequest,
) -> HttpResponse:
    form_status = HTTPStatus.BAD_REQUEST
    if request.method == "POST":
        form = AddRecordForm(request.POST)
        if form.is_valid():
            zone_name: str = form.cleaned_data["zone_name"]
            rr_content: str = form.cleaned_data["rr_content"]

            zone = Zone.objects.filter(
                name=zone_name,
                owner=request.user,
            ).first()
            if not zone:
                raise CustomExceptionBadRequest(
                    "Subdomain does not exist, or you are not the owner",
                    status_code=404,
                )

            rr_name = f"{ACME_CHALLENGE_LABEL}.{zone.name}"
            update_txt_record_helper(
                request=request,
                zone_name=zone.name,
                rr_name=rr_name,
                edit_action=EditActionEnum.ADD,
                rr_content=rr_content,
                is_web_request=True,
            )

            return redirect(
                build_url(
                    "describe_zone",
                    params={"zone_name": zone.name},
                )
            )
    else:
        assert request.method == "GET"
        form = AddRecordForm(
            initial=request.GET,
        )
        form_status = HTTPStatus.OK
    return render(
        request, "create_resource_record.html", {"form": form}, status=form_status
    )


class EditActionEnum(Enum):
    ADD = 1
    REMOVE = 2


def update_txt_record_helper(
    request: HttpRequest,
    zone_name: str,
    rr_name: str,
    edit_action: EditActionEnum,
    rr_content: str,
    is_web_request: str,
):
    new_content = f'"{rr_content}"'  # Normalize
    existing_content = get_existing_txt_records(zone_name, rr_name)

    # Pull out SPF record(s) so we don't change those
    existing_spf_records = [_ for _ in existing_content if _ == DEFAULT_SPF_POLICY]
    assert len(existing_spf_records) <= 1
    existing_user_defined = [_ for _ in existing_content if _ != DEFAULT_SPF_POLICY]

    if edit_action == EditActionEnum.ADD:
        if any([new_content == existing for existing in existing_user_defined]):
            if is_web_request:
                messages.warning(request, "Record already exists")
            return

        if len(existing_user_defined) < TXT_RECORDS_PER_RRSET_LIMIT:
            # existing content set is small enough, just merge in the new content
            new_content_set = existing_user_defined
        elif is_web_request:
            # In the web interface, the user should delete records manually
            raise CustomExceptionBadRequest(
                "Limit exceeded, unable to add additional TXT records. Try deleting unneeded records."
            )
        else:
            # keep only the newest of the existing user defined content
            new_content_set = [existing_user_defined[-1]]
        new_content_set.append(new_content)
    else:
        assert edit_action == EditActionEnum.REMOVE
        new_content_set = [
            item for item in existing_user_defined if item != new_content
        ]
        if len(new_content_set) == len(existing_user_defined):
            if is_web_request:
                messages.warning(request, "Nothing was removed")
            return

    # Always keep the SPF if it previously existed
    new_content_set.extend(existing_spf_records)

    if new_content_set:
        logging.info(f"Updating RRSET {rr_name} TXT with {len(new_content_set)} values")
        # Replace to update the content
        pdns_replace_rrset(zone_name, rr_name, "TXT", 1, new_content_set)
    else:
        logging.info(f"Deleting RRSET {rr_name} TXT")
        # Nothing remaining, delete the rr_set
        pdns_delete_rrset(zone_name, rr_name, "TXT")
    if is_web_request:
        if edit_action == EditActionEnum.ADD:
            messages.success(request, "Record added")
        else:
            messages.success(request, "Record removed")


def get_existing_txt_records(zone_name: str, rr_name: str) -> List[str]:
    details = pdns_describe_domain(zone_name)
    existing_records = []
    existing_comments = []
    if details["rrsets"]:
        for rrset in details["rrsets"]:
            if rrset["name"] == rr_name and rrset["type"] == "TXT":
                existing_records = rrset["records"]
                existing_comments = rrset["comments"]
                break

    # Check invariants
    for record in existing_records:
        assert all([comment["content"] for comment in existing_comments])
        assert any(
            [
                comment["content"].startswith(f"{record['content']} : ")
                for comment in existing_comments
            ]
        )
    assert len(existing_comments) == len(existing_records)

    # Each comment will contain "<content> : <index>" where <content> matches the TXT record
    # content and <index> tracks the order these were added (oldest at index 0)
    # Sort these so we can trim old content if needed
    ordered_comments = sorted(
        existing_comments, key=lambda x: int(x["content"].split(" : ")[1])
    )
    ordered_content = [
        comment["content"].split(" : ")[0] for comment in ordered_comments
    ]
    return ordered_content
