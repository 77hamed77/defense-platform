# apk_analyzer/admin.py
from django.contrib import admin
from .models import APKAnalysis, APKFinding

@admin.register(APKAnalysis)
class APKAnalysisAdmin(admin.ModelAdmin):
    list_display = ("filename", "package_name", "status", "created_at", "fallback_activity")
    search_fields = ("filename", "package_name", "fallback_activity")
    list_filter = ("status", "fallback_activity")  # 👈 فلتر إضافي
    fields = (
        "filename",
        "package_name",
        "sha256_hash",
        "apk_file",
        "status",
        "fallback_activity",  # 👈 يظهر في الفورم
        "created_at",
        "completed_at",
    )
    readonly_fields = ("created_at", "completed_at")


@admin.register(APKFinding)
class APKFindingAdmin(admin.ModelAdmin):
    list_display = ("analysis", "type", "severity", "description")
    search_fields = ("description", "type")
    list_filter = ("severity", "type")