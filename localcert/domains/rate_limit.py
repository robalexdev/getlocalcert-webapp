from .models import Zone
from django.utils import timezone
from datetime import timedelta
from .constants import (
    INSTANT_DOMAINS_PER_HOUR,
    INSTANT_DOMAINS_PER_DAY_BURST,
    INSTANT_DOMAINS_PER_WEEK,
)


def should_instant_domain_creation_throttle() -> bool:
    now = timezone.now()
    past_week = now - timedelta(weeks=1)
    past_day = now - timedelta(days=1)
    past_hour = now - timedelta(hours=1)

    week_count = Zone.objects.filter(
        created__gt=past_week,
        owner__isnull=True,
        is_delegate=False,  # These shouldn't impact Let's Encrypt rate limit
    ).count()

    day_count = Zone.objects.filter(
        created__gt=past_day,
        owner__isnull=True,
        is_delegate=False,
    ).count()

    hour_count = Zone.objects.filter(
        created__gt=past_hour,
        owner__isnull=True,
        is_delegate=False,
    ).count()

    if hour_count >= INSTANT_DOMAINS_PER_HOUR:
        # This is high, but allow it if the day has otherwise been slow
        # This supports quick spikes
        if day_count >= INSTANT_DOMAINS_PER_DAY_BURST:
            # A busy week and hour, stop it
            return True
    return week_count >= INSTANT_DOMAINS_PER_WEEK
