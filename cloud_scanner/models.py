# cloud_scanner/models.py
from django.db import models
import uuid

class AWSEnvironment(models.Model):
    name = models.CharField(max_length=200, unique=True)
    access_key_id = models.CharField(max_length=255)
    secret_access_key = models.CharField(max_length=255) # ملاحظة: في الإنتاج، يجب تشفير هذا الحقل
    default_region = models.CharField(max_length=100, default="us-east-1")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

class CloudScan(models.Model):
    class Status(models.TextChoices):
        PENDING = 'PENDING', 'Pending'
        ANALYZING = 'ANALYZING', 'Analyzing'
        COMPLETED = 'COMPLETED', 'Completed'
        FAILED = 'FAILED', 'Failed'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    environment = models.ForeignKey(AWSEnvironment, on_delete=models.CASCADE, related_name='scans')
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    task_id = models.CharField(max_length=255, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Prowler scan for {self.environment.name} at {self.created_at}"

class CloudFinding(models.Model):
    scan = models.ForeignKey(CloudScan, on_delete=models.CASCADE, related_name='findings')
    status = models.CharField(max_length=50) # PASS or FAIL
    severity = models.CharField(max_length=50)
    service_name = models.CharField(max_length=100)
    region = models.CharField(max_length=100)
    resource_id = models.CharField(max_length=500)
    description = models.TextField()
    remediation = models.TextField()
    details = models.JSONField()
    ai_analysis = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"[{self.severity}] {self.description[:80]}"