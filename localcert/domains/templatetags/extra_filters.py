from django import template


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
    if value.endswith('.'):
        value = value[0:-1]
    return value
