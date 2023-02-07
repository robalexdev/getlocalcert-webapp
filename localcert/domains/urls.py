from django.urls import path

from . import views

urlpatterns = [
    path("", views.list_zones, name="list_zones"),
    path("create_free_domain", views.create_free_domain, name="create_free_domain"),
    path("domain/<str:zone_name>/", views.describe_zone, name="describe_zone"),
    # Create / Delete Records
    path(
        "domain/<str:zone_name>/record/",
        views.create_resource_record_page,
        name="create_resource_record_page",
    ),
    path(
        "record/<str:rr_name>/",
        views.modify_rrset,
        name="modify_rrset",
    ),
    path(
        "domain/<str:zone_name>/apikey/",
        views.create_zone_api_key,
        name="create_zone_api_key",
    ),
    path(
        "domain/<str:zone_name>/delete-apikey/",
        views.delete_zone_api_key,
        name="delete_zone_api_key",
    ),
    # ACME DNS APIs are namespaced
    path(
        "acmedns-api/health",
        views.acmedns_api_health,
        name="acmedns_api_health",
    ),
    path(
        "acmedns-api/update",
        views.acmedns_api_update,
        name="acmedns_api_update",
    ),
    path(
        "acmedns-api/check",
        views.acmedns_api_extra_check,
        name="acmedns_api_extra_check",
    ),
]
