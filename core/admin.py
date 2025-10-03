# core/admin.py

from django.contrib import admin
from .models import Asset, Alert, IndicatorOfCompromise, Playbook, ActionLog

# تسجيل النماذج هنا لتظهر في لوحة التحكم
admin.site.register(Asset)
admin.site.register(Alert)
admin.site.register(IndicatorOfCompromise)
admin.site.register(Playbook) 
admin.site.register(ActionLog)