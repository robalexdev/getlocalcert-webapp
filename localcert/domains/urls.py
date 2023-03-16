from . import views
from django.urls import path

urlpatterns = [
    path("", views.list_zones, name="list_zones"),
    path("accounts/login/", views.login_page, name="login"),
    path("create-free-domain", views.create_free_domain, name="create_free_domain"),
    path("describe-zone", views.describe_zone, name="describe_zone"),
    path(
        "add-record",
        views.add_record,
        name="add_record",
    ),
    path(
        "delete-record",
        views.delete_record,
        name="delete_record",
    ),
    path(
        "create-zone-api-key",
        views.create_zone_api_key,
        name="create_zone_api_key",
    ),
    path(
        "delete-zone-api-key",
        views.delete_zone_api_key,
        name="delete_zone_api_key",
    ),
    # API paths are versioned
    path(
        "api/v1/health",
        views.acmedns_api_health,
        name="acmedns_api_health",
    ),
    path(
        "api/v1/check",
        views.acmedns_api_extra_check,
        name="acmedns_api_extra_check",
    ),
    # ACME DNS APIs are namespaced
    path(
        "acmedns-api-v1/update",
        views.acmedns_api_update,
        name="acmedns_api_update",
    ),
]
