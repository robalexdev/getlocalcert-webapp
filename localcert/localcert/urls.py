"""localcert URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path, include
from allauth.account import views as allauth_views
from allauth.socialaccount.providers.github.views import oauth2_login, oauth2_callback

urlpatterns = [
    path("", include("domains.urls")),
    # Route each allauth view manually to block some extra views we don't use
    path("accounts/logout/", allauth_views.logout, name="account_logout"),
    path("accounts/github/login/", oauth2_login, name="github_login"),
    path("accounts/github/login/callback/", oauth2_callback, name="github_callback"),
]
