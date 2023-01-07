from django.urls import path

from . import views

urlpatterns = [
    path("", views.list_domains, name="list_domains"),
    path("create_free_domain", views.create_free_domain, name="create_free_domain"),
    path("domain/<str:domain_id>/", views.describe_domain, name="describe_domain"),
    path(
        "domain/<str:domain_id>/subdomain/", views.add_subdomain, name="add_subdomain"
    ),
    path(
        "subdomain/<str:subdomain_id>/",
        views.describe_subdomain,
        name="describe_subdomain",
    ),
    path(
        "subdomain/<str:subdomain_id>/delete",
        views.delete_subdomain,
        name="delete_subdomain",
    ),
    path(
        "subdomain/<str:subdomain_id>/record/",
        views.create_resource_record,
        name="create_resource_record",
    ),
    path(
        "subdomain/<str:subdomain_id>/apiKey/",
        views.create_api_key,
        name="create_api_key",
    ),
    path("apiKey/<str:keyId>/delete/", views.delete_api_key, name="delete_api_key"),
    path(
        "record/<str:record_id>/",
        views.delete_resource_record,
        name="delete_resource_record",
    ),
]
