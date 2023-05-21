from django.http import HttpResponse
from django.test import TestCase
from django.urls import reverse
from uuid import uuid4
from .views import instant_subdomain
from .models import Zone
from .constants import (
    INSTANT_DOMAINS_PER_HOUR,
    INSTANT_DOMAINS_PER_DAY_BURST,
    INSTANT_DOMAINS_PER_WEEK,
)
from datetime import timedelta
from django.utils import timezone


class TestRateLimit(TestCase):
    def assertInstantSubdomainCanBeCreated(self):
        response = self.client.post(reverse(instant_subdomain))
        self.assertContains(response, "Subdomain created", status_code=201)

    def assertInstantSubdomainCreationWillThrottle(self):
        response = self.client.post(reverse(instant_subdomain), follow=True)
        self.assertContains(
            response,
            "Too many instant domains have been created recently. Try again later.",
            status_code=200,
        )

    def bulkCreateInstantDomains(self, N: int, age: timedelta = timedelta(seconds=0)):
        now = timezone.now()
        for _ in range(N):
            Zone.objects.create(name=uuid4(), created=now - age)

    def test_unthrottle_low_load(self):
        # count = 0 => OK
        self.assertInstantSubdomainCanBeCreated()

    def test_use_daily_limit(self):
        self.bulkCreateInstantDomains(
            INSTANT_DOMAINS_PER_HOUR, age=timedelta(minutes=5)
        )
        # day_count < limit, hour_count = limit => OK
        self.assertInstantSubdomainCanBeCreated()

    def test_throttle_breach_daily_limit(self):
        self.bulkCreateInstantDomains(
            INSTANT_DOMAINS_PER_DAY_BURST, age=timedelta(minutes=5)
        )
        # day_count = limit, hour_count = limit => throttle
        self.assertInstantSubdomainCreationWillThrottle()

    def test_throttle_breach_daily_limit_reset(self):
        self.bulkCreateInstantDomains(
            INSTANT_DOMAINS_PER_DAY_BURST, age=timedelta(hours=1.1)
        )
        # day_count = limit, hour_count = 0 => OK
        self.assertInstantSubdomainCanBeCreated()

    def test_throttle_weekly_limits(self):
        self.bulkCreateInstantDomains(
            INSTANT_DOMAINS_PER_DAY_BURST, age=timedelta(days=5)
        )
        # week_count = limit => throttle
        self.assertInstantSubdomainCreationWillThrottle

    def test_throttle_weekly_limits_reset(self):
        self.bulkCreateInstantDomains(
            INSTANT_DOMAINS_PER_DAY_BURST, age=timedelta(days=8)
        )
        # week_count=0 => OK
        self.assertInstantSubdomainCanBeCreated()
