"""
Django settings for localcert project.

Generated by 'django-admin startproject' using Django 4.1.4.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""

import os

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

#
# Settings from environmental variables
#

SECRET_KEY = os.environ["LOCALCERT_WEB_DJANGO_SECRET_KEY"]
# Key rotation, keep these for only a short time
SECRET_KEY_FALLBACKS = []

GITHUB_CLIENT_ID = os.environ["LOCALCERT_WEB_GITHUB_CLIENT_ID"]
GITHUB_SECRET = os.environ["LOCALCERT_WEB_GITHUB_SECRET"]


DEBUG = os.environ.get("LOCALCERT_WEB_DEBUG", "False") == "True"

ALLOWED_HOSTS = [
    "console.getlocalcert.net",
    "api.getlocalcert.net",
]

if DEBUG:
    ALLOWED_HOSTS.append("127.0.0.1")

if not DEBUG:  # pragma: no cover
    CSRF_TRUSTED_ORIGINS = ["https://console.getlocalcert.net"]


# Application definition

INSTALLED_APPS = [
    # Debug Toolbar
    # "debug_toolbar",
    "domains.apps.DomainsConfig",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Needed for django-allauth
    "django.contrib.sites",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    # Only permit GitHub
    "allauth.socialaccount.providers.github",
]

SITE_ID = 1

SOCIALACCOUNT_PROVIDERS = {
    "github": {
        "APP": {
            "client_id": GITHUB_CLIENT_ID,
            "secret": GITHUB_SECRET,
        }
    }
}

LOGIN_REDIRECT_URL = "/"

MIDDLEWARE = [
    # Debug Toolbar
    # "debug_toolbar.middleware.DebugToolbarMiddleware",
    "csp.middleware.CSPMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

ROOT_URLCONF = "localcert.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "localcert.wsgi.application"


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ["LOCALCERT_WEB_DB_NAME"],
        "USER": os.environ["POSTGRES_USER"],
        "PASSWORD": os.environ["POSTGRES_PASSWORD"],
        "HOST": os.environ["LOCALCERT_WEB_PGSQL_HOST"],
        "PORT": "5432",
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Authentication
# https://django-allauth.readthedocs.io/en/latest/installation.html

AUTHENTICATION_BACKENDS = [
    # Disable login via username, OAuth flow only
    # 'django.contrib.auth.backends.ModelBackend',
    # `allauth` specific authentication methods, such as login by e-mail
    "allauth.account.auth_backends.AuthenticationBackend",
]

AUTH_USER_MODEL = "domains.User"


INTERNAL_IPS = [
    # Debug Toolbar
    # "127.0.0.1",
]

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "DEBUG",
    },
}

# CSP settings
# See: https://django-csp.readthedocs.io/en/latest/configuration.html
CSP_DEFAULT_SRC = ("'none'",)
CSP_IMG_SRC = ("'self'",)
CSP_STYLE_SRC = ("https://cdn.jsdelivr.net",)
CSP_INCLUDE_NONCE_IN = ["script-src"]


# App specific settings

LOCALCERT_PDNS_SERVER_IP = os.environ["LOCALCERT_WEB_PDNS_HOST"]
LOCALCERT_PDNS_API_PORT = os.environ["LOCALCERT_WEB_PDNS_API_PORT"]
LOCALCERT_PDNS_API_KEY = os.environ["LOCALCERT_SHARED_PDNS_API_KEY"]
LOCALCERT_PDNS_DNS_PORT = int(os.environ["LOCALCERT_WEB_PDNS_DNS_PORT"])
LOCALCERT_PDNS_NS1 = os.environ["LOCALCERT_PDNS_NS1"]
LOCALCERT_PDNS_NS2 = os.environ["LOCALCERT_PDNS_NS2"]

# Security settings
# SESSION_COOKIE_AGE default is two weeks
if not DEBUG:  # pragma: no cover
    SECURE_HSTS_SECONDS = 1209600  # two weeks
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True

# Prod concerns
ACCOUNT_DEFAULT_HTTP_PROTOCOL = os.environ[
    "LOCALCERT_WEB_ACCOUNT_DEFAULT_HTTP_PROTOCOL"
]
