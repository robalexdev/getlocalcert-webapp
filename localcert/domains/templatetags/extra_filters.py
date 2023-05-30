from django import template
from ..utils import parent_zone_name as util_parent_zone_name


register = template.Library()


@register.filter
def strip_quot(value: str):
    if value.startswith('"'):
        value = value[1:]
    if value.endswith('"'):
        value = value[0:-1]
    return value


@register.filter
def strip_trailing_dot(value: str):
    if value.endswith("."):
        value = value[0:-1]
    return value


@register.filter
def strip_domain_name(value: str):
    if value.endswith("."):
        value = value[0:-1]
    parts = value.split(".")
    parts.pop()  # net
    parts.pop()  # localhostcert / localcert
    parts.pop()  # <domain>
    if len(parts) == 0:
        return "@"
    return ".".join(parts)


@register.filter
def startswith(value: str, arg: str):
    return value.startswith(arg)


@register.filter
def namedDuration(value: str):
    i = int(value)
    if i % (24 * 60 * 60) == 0:
        i //= 24 * 60 * 60
        return pluralize(i, "day")
    if i % (60 * 60) == 0:
        i //= 60 * 60
        return pluralize(i, "hour")
    if i % 60 == 0:
        i //= 60
        return pluralize(i, "minute")
    return pluralize(i, "second")


def pluralize(i: int, name: str):
    if i <= 1:
        return f"{i} {name}"
    else:
        return f"{i} {name}s"


@register.filter
def parent_zone_name(value: str):
    return util_parent_zone_name(value, soft_error=True)
