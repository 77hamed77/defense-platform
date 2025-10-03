# core/serializers.py

from rest_framework import serializers
from .models import Alert, Scan # <-- أضف Scan

class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        # حدد الحقول التي تريد استقبالها عبر الـ API
        fields = [
            'timestamp', 
            'description', 
            'severity', 
            'source_ip', 
            'destination_ip', 
            'source_tool', 
            'raw_log'
        ]

class ScanStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Scan
        fields = ['id', 'status', 'get_status_display'] # 'get_status_display' لإرجاع النص удобочитаемый