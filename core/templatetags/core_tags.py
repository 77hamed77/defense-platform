# core/templatetags/core_tags.py

import json
from django import template
from django.utils.safestring import mark_safe

register = template.Library()

@register.filter(name='pretty_json')
def pretty_json(value):
    """
    Converts a dictionary to a formatted JSON string for display in templates.
    """
    if value is None:
        return ""
    # تحويل القاموس إلى سلسلة JSON منسقة مع مسافة بادئة 4
    formatted_json = json.dumps(value, indent=4)
    # استخدام mark_safe لمنع Django من الهروب من الأحرف الخاصة في الـ HTML
    return mark_safe(f"<pre class='bg-gray-900 p-4 rounded-md text-sm text-yellow-300 overflow-x-auto'>{formatted_json}</pre>")