from django.db.models import Q
from django.http import (
    HttpResponse,
    HttpRequest,
    Http404,
    HttpResponseServerError,
    HttpResponseBadRequest,
)
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.db.models import Prefetch

from .models import (
    Domain,
    DomainNameHelper,
    Subdomain,
    Record,
    RecordApiKey,
    create_subdomain,
    create_record_api_key,
)


DOMAIN_LIMIT = 3
SUBDOMAIN_LIMIT = 3


@login_required
def list_domains(request: HttpRequest) -> HttpResponse:
    domains = (
        Domain.objects.filter(
            owner=request.user,
        )
        .order_by(
            "created",
        )
        .prefetch_related(
            "subdomains",
        )
    )

    domains = [_ for _ in domains]

    return render(
        request,
        "list_domains.html",
        {
            "domains": domains,
            "domain_limit": DOMAIN_LIMIT,
        },
    )


@login_required
def create_free_domain(request: HttpRequest) -> HttpResponse:
    domain_count = Domain.objects.filter(
        owner=request.user,
    ).count()

    if domain_count >= DOMAIN_LIMIT:
        return HttpResponseBadRequest("Domain limit already reached")

    newName = DomainNameHelper.objects.create()
    newDomain = Domain.objects.create(
        name=newName.get_name(),
        owner=request.user,
    )

    # TODO success message

    return redirect(
        "describe_domain",
    )


@login_required
def describe_domain(request: HttpRequest, domain_id: str) -> HttpResponse:
    domain_list = Domain.objects.filter(
        pk=domain_id,
        owner=request.user,
    ).prefetch_related(
        "subdomains",
    )

    domain_list = [_ for _ in domain_list]
    if not domain_list:
        raise Http404("Domain does not exist, or you are not the owner")
    if len(domain_list) > 1:
        return HttpResponseServerError("Unable to process request")

    domain = domain_list[0]
    subdomains = [_ for _ in domain.subdomains.all()]

    return render(
        request,
        "domain_detail.html",
        {
            "domain": domain,
            "subdomains": subdomains,
        },
    )


@login_required
def describe_subdomain(request: HttpRequest, subdomain_id: str) -> HttpResponse:
    if request.method != "GET":
        return HttpResponseBadRequest("Must use HTTP GET")

    subdomain_list = Subdomain.objects.filter(pk=subdomain_id,).prefetch_related(
        "domain",
        "domain__owner",
        "apiKeys",
        "records",
    )

    if not subdomain_list:
        raise Http404("Subdomain does not exist")
    if len(subdomain_list) > 1:
        return HttpResponseServerError("Unable to process request")

    subdomain = subdomain_list[0]
    domain = subdomain.domain
    if domain.owner != request.user:
        # permission error, pretend the subdomain doesn't exist
        raise Http404("Subdomain does not exist")

    records = [_ for _ in subdomain.records.all()]
    apiKeys = [_ for _ in subdomain.apiKeys.all()]
    return render(
        request,
        "subdomain_detail.html",
        {
            "domain": domain,
            "subdomain": subdomain,
            "apiKeys": apiKeys,
            "records": records,
        },
    )


@login_required
def delete_subdomain(request: HttpRequest, subdomain_id: str) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseBadRequest("Must use POST")

    subdomain_list = Subdomain.objects.filter(pk=subdomain_id,).prefetch_related(
        "domain__owner",
    )

    if not subdomain_list:
        raise Http404("Subdomain does not exist")
    if len(subdomain_list) > 1:
        return HttpResponseServerError("Unable to process request")

    subdomain = subdomain_list[0]
    domain = subdomain.domain
    if domain.owner != request.user:
        # permission error, pretend the subdomain doesn't exist
        raise Http404("Subdomain does not exist")

    subdomain.delete()
    return redirect(
        "describe_domain",
        domain_id=domain.id,
    )


@login_required
def add_subdomain(request: HttpRequest, domain_id: str) -> HttpResponse:
    if request.method != "POST":
        return HttpResponseBadRequest("Must use HTTP POST")

    domain_list = Domain.objects.filter(
        owner=request.user,
        pk=domain_id,
    ).prefetch_related(
        "subdomains",
    )

    if not domain_list:
        raise Http404("Domain does not exist, or you are not the owner")
    if len(domain_list) > 1:
        return HttpResponseServerError("Unable to process request")

    domain = domain_list[0]

    subdomains = [_ for _ in domain.subdomains.all()]
    if len(subdomains) >= SUBDOMAIN_LIMIT:
        return HttpResponseBadRequest(
            "Cannot create more subdomains, subdomain limit reached."
        )

    subdomain_name = request.POST["subdomain"]

    # TODO check valid label

    result = create_subdomain(domain=domain, name=subdomain_name)
    if result is None:
        return HttpResponse("Subdomain already exists")

    return render(
        request,
        "show_new_subdomain_api_key.html",
        {
            "domain": domain,
            "subdomain": result.subdomain,
            "secretKeyId": result.keyObject.id,
            "secretKey": result.secretKey,
        },
    )


@login_required
def delete_api_key(request: HttpRequest, keyId: str) -> HttpResponse:
    api_key_list = RecordApiKey.objects.filter(pk=keyId,).prefetch_related(
        "subdomain__domain__owner",
    )

    if not api_key_list:
        raise Http404("Cannot find key")
    if len(api_key_list) > 1:
        return HttpResponseServerError("Cannot process request")
    apiKey = api_key_list[0]
    subdomain = apiKey.subdomain

    if subdomain.domain.owner != request.user:
        # permission error, pretend the key doesn't exist
        raise Http404("Cannot find key")

    if request.method == "POST":
        apiKey.delete()
        # TODO message about delete success
        return redirect(
            "describe_subdomain",
            subdomain_id=str(subdomain.id),
        )
    elif request.method == "GET":
        return render(
            request,
            "confirm_api_key_delete.html",
            {
                "domain": subdomain.domain,
                "subdomain": subdomain,
                "targetKey": apiKey,
            },
        )
    else:
        return HttpResponseBadRequest("GET or POST only")


@login_required
def create_api_key(request: HttpRequest, subdomain_id: str) -> HttpResponse:
    subdomain_list = Subdomain.objects.filter(pk=subdomain_id,).prefetch_related(
        "apiKeys",
        "domain",
        "domain__owner",
    )

    subdomain_list = [_ for _ in subdomain_list]
    if not subdomain_list:
        raise Http404("Subdomain not found")
    if len(subdomain_list) > 1:
        return HttpResponseServerError("Unable to process request")

    subdomain = subdomain_list[0]
    if subdomain.domain.owner != request.user:
        # permission error, pretend the key doesn't exist
        raise Http404("Key not found")

    if subdomain.apiKeys.count() >= 2:
        return HttpResponseBadRequest("Cannot create additional keys, limit reached")

    createdKey, secretKey = create_record_api_key(subdomain)
    return render(
        request,
        "show_new_subdomain_api_key.html",
        {
            "domain": subdomain.domain,
            "subdomain": subdomain,
            "secretKeyId": createdKey.id,
            "secretKey": secretKey,
        },
    )


@login_required
def create_resource_record(request: HttpRequest, subdomain_id: str) -> HttpResponse:
    if request.method not in ["POST", "GET"]:
        return HttpResponseBadRequest("Use POST or GET")

    subdomain_list = Subdomain.objects.filter(pk=subdomain_id,).prefetch_related(
        "domain__owner",
    )

    subdomain_list = [_ for _ in subdomain_list]
    if not subdomain_list:
        raise Http404("No such subdomain")
    if len(subdomain_list) > 1:
        return HttpResponseServerError("Unable to process request")
    subdomain = subdomain_list[0]

    domain = subdomain.domain
    if domain.owner != request.user:
        # permission issue, pretend the subdomain doesn't exist
        raise Http404("No such subdomain")

    if request.method == "POST":
        value = request.POST["value"]
        Record.objects.create(
            subdomain=subdomain,
            value=value,
        )
        return redirect(
            "describe_subdomain",
            subdomain_id=subdomain.id,
        )
    else:
        return render(
            request,
            "create_resource_record.html",
            {
                "domain": domain,
                "subdomain": subdomain,
            },
        )


@login_required
def delete_resource_record(request: HttpRequest, record_id: str) -> HttpResponse:
    if request.method not in ["POST", "GET"]:
        return HttpResponseBadRequest("Use POST or GET")

    record_list = Record.objects.filter(pk=record_id,).prefetch_related(
        "subdomain",
        "subdomain__domain",
        "subdomain__domain__owner",
    )

    record_list = [_ for _ in record_list]
    if not record_list:
        raise Http404("Record not found")
    if len(record_list) > 1:
        return HttpResponseServerError("Unable to process request")
    record = record_list[0]

    subdomain = record.subdomain
    domain = subdomain.domain
    if domain.owner != request.user:
        # permission issue, pretend it doesn't exist
        raise Http404("Record not found")

    if request.method == "POST":
        record.delete()
        return redirect(
            "describe_subdomain",
            subdomain_id=subdomain.id,
        )
    else:
        return render(
            request,
            "confirm_record_delete.html",
            {
                "domain": domain,
                "subdomain": subdomain,
                "record": record,
            },
        )
