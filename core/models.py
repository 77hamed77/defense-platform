# core/models.py

from django.db import models
from django.utils.translation import gettext_lazy as _

# النموذج الأول: الأصل (Asset)
# يمثل أي جهاز أو خادم في الشبكة
class Asset(models.Model):
    ip_address = models.GenericIPAddressField(unique=True, verbose_name=_("IP Address"))
    hostname = models.CharField(max_length=255, blank=True, null=True, verbose_name=_("Hostname"))
    mac_address = models.CharField(max_length=17, blank=True, null=True, verbose_name=_("MAC Address"))
    os = models.CharField(max_length=100, blank=True, null=True, verbose_name=_("Operating System"))
    is_critical = models.BooleanField(default=False, verbose_name=_("Is Critical?"))
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.hostname or self.ip_address

# النموذج الثاني: التنبيه (Alert)
# يمثل أي حدث أمني يتم اكتشافه
class Alert(models.Model):
    # تعريف مستويات الخطورة
    class Severity(models.TextChoices):
        LOW = 'LOW', _('Low')
        MEDIUM = 'MEDIUM', _('Medium')
        HIGH = 'HIGH', _('High')
        CRITICAL = 'CRITICAL', _('Critical')

    # تعريف حالة معالجة التنبيه
    class Status(models.TextChoices):
        NEW = 'NEW', _('New')
        IN_PROGRESS = 'IN_PROGRESS', _('In Progress')
        RESOLVED = 'RESOLVED', _('Resolved')
        FALSE_POSITIVE = 'FALSE_POSITIVE', _('False Positive')

    timestamp = models.DateTimeField(verbose_name=_("Timestamp"))
    description = models.TextField(verbose_name=_("Description"))
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.LOW, verbose_name=_("Severity"))
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NEW, verbose_name=_("Status"))
    
    source_ip = models.GenericIPAddressField(blank=True, null=True, verbose_name=_("Source IP"))
    destination_ip = models.GenericIPAddressField(blank=True, null=True, verbose_name=_("Destination IP"))
    
    # ربط التنبيه بأصل معين (إذا كان ذلك ممكناً)
    related_asset = models.ForeignKey(Asset, on_delete=models.SET_NULL, null=True, blank=True, verbose_name=_("Related Asset"))

    source_tool = models.CharField(max_length=100, help_text="e.g., Suricata, Wazuh, Splunk", verbose_name=_("Source Tool"))
    
    raw_log = models.JSONField(blank=True, null=True, verbose_name=_("Raw Log Data")) # لتخزين السجل الخام بصيغة JSON

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.severity} Alert from {self.source_tool} at {self.timestamp.strftime('%Y-%m-%d %H:%M')}"

# النموذج الثالث: مؤشر الاختراق (Indicator of Compromise - IOC)
class IndicatorOfCompromise(models.Model):
    class IOCType(models.TextChoices):
        IP_ADDRESS = 'IP', _('IP Address')
        DOMAIN = 'DOMAIN', _('Domain Name')
        FILE_HASH = 'HASH', _('File Hash') # e.g., MD5, SHA256
        URL = 'URL', _('URL')

    ioc_type = models.CharField(max_length=10, choices=IOCType.choices, verbose_name=_("IOC Type"))
    value = models.CharField(max_length=500, unique=True, verbose_name=_("Value"))
    source = models.CharField(max_length=100, blank=True, null=True, help_text="e.g., MISP, VirusTotal", verbose_name=_("Source"))
    
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    def __str__(self):
        return f"[{self.ioc_type}] {self.value}"
    
# النموذج الرابع: كتاب اللعب (Playbook)
class Playbook(models.Model):
    name = models.CharField(max_length=200, unique=True, verbose_name=_("Playbook Name"))
    description = models.TextField(blank=True, null=True, verbose_name=_("Description"))
    is_active = models.BooleanField(default=True, verbose_name=_("Is Active?"))

    def __str__(self):
        return self.name

# النموذج الخامس: سجل الإجراءات (Action Log)
class ActionLog(models.Model):
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='actions')
    playbook_run = models.ForeignKey(Playbook, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.CharField(max_length=500)
    
    class Meta:
        ordering = ['-timestamp'] # ترتيب السجلات من الأحدث إلى الأقدم

    def __str__(self):
        return f"Playbook '{self.playbook_run.name}' run on Alert #{self.alert.id}"
    
# النموذج السادس: عملية الفحص (Scan)
class Scan(models.Model):
    class Status(models.TextChoices):
        PENDING = 'PENDING', _('Pending')
        RUNNING = 'RUNNING', _('Running')
        COMPLETED = 'COMPLETED', _('Completed')
        FAILED = 'FAILED', _('Failed')

    target_url = models.URLField(max_length=500, verbose_name=_("Target URL"))
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"Scan for {self.target_url} ({self.status})"

# النموذج السابع: الثغرة المكتشفة (Vulnerability)
class Vulnerability(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    description = models.TextField()
    severity = models.CharField(max_length=20) # e.g., High, Medium, Low
    cve_id = models.CharField(max_length=50, blank=True, null=True) # مثل CVE-2022-1234
    details = models.JSONField() # لتخزين كل تفاصيل Nikto

    def __str__(self):
        return self.description[:80]