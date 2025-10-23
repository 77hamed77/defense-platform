# cloud_scanner/admin.py
from django.contrib import admin
from .models import AWSEnvironment, CloudScan, CloudFinding

admin.site.register(AWSEnvironment)
admin.site.register(CloudScan)
admin.site.register(CloudFinding)