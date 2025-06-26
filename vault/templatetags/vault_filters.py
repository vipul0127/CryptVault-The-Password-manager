# cryptvault/vault/templatetags/vault_filters.py
from django import template

register = template.Library()

@register.filter
def split(value, delimiter=','):
    """
    Splits a string by the given delimiter and returns a list.
    Usage: {{ entry.tags|split:"," }}
    """
    if not isinstance(value, str):
        return []
    return [item.strip() for item in value.split(delimiter) if item.strip()]