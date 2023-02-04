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
]
