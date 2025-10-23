# apk_analyzer/models.py
from django.db import models
from django.utils.translation import gettext_lazy as _
import uuid

class APKAnalysis(models.Model):
    class Status(models.TextChoices):
        PENDING = 'PENDING', _('Pending')
        ANALYZING = 'ANALYZING', _('Analyzing')
        COMPLETED = 'COMPLETED', _('Completed')
        FAILED = 'FAILED', _('Failed')

    # معلومات الملف
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    apk_file = models.FileField(upload_to='apk_files/')
    filename = models.CharField(max_length=255)
    sha256_hash = models.CharField(max_length=64, unique=True)
    fallback_activity = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        help_text="Optional: specify fallback activity to launch if monkey fails (e.g., .LoginActivity)"
    )
    
    # معلومات التطبيق (سيتم ملؤها لاحقًا)
    package_name = models.CharField(max_length=255, blank=True, null=True)
    version_name = models.CharField(max_length=100, blank=True, null=True)

    # حالة التحليل
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.filename or self.package_name

class APKFinding(models.Model):
    class Severity(models.TextChoices):
        INFO = 'INFO', _('Informational')
        LOW = 'LOW', _('Low')
        MEDIUM = 'MEDIUM', _('Medium')
        HIGH = 'HIGH', _('High')
        CRITICAL = 'CRITICAL', _('Critical')

    analysis = models.ForeignKey(APKAnalysis, on_delete=models.CASCADE, related_name='findings')
    type = models.CharField(max_length=100, help_text="e.g., Dangerous Permission, Leaked Secret, Exported Component")
    description = models.TextField()
    severity = models.CharField(max_length=20, choices=Severity.choices, default=Severity.INFO)
    details = models.JSONField(null=True, blank=True)
    ai_analysis = models.TextField(blank=True, null=True, help_text="AI-generated analysis of the finding")

    def __str__(self):
        return f"[{self.severity}] {self.type} in {self.analysis.filename}"