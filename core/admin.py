# core/admin.py

from django.contrib import admin
from .models import Asset, Alert, IndicatorOfCompromise, Playbook, ActionLog, Tool, Scan, Vulnerability
from django.contrib import admin
from .models import (
    Asset, Alert, IndicatorOfCompromise, Playbook, ActionLog, Tool, 
    Scan, Vulnerability, EmailTemplate, LandingPage, PhishingTarget, 
    PhishingCampaign, PhishingResult
)
# 👈 فئة جديدة لتحسين عرض الأدوات
@admin.register(Tool)
class ToolAdmin(admin.ModelAdmin):
    list_display = ('name', 'executable_path', 'is_active')
    search_fields = ('name', 'description')
    list_filter = ('is_active',)

# تسجيل النماذج هنا لتظهر في لوحة التحكم
admin.site.register(Asset)
admin.site.register(Alert)
admin.site.register(IndicatorOfCompromise)
admin.site.register(Playbook) 
admin.site.register(ActionLog)
admin.site.register(Scan)
admin.site.register(Vulnerability)
admin.site.register(EmailTemplate)
admin.site.register(LandingPage)
admin.site.register(PhishingTarget)
admin.site.register(PhishingCampaign)
admin.site.register(PhishingResult)