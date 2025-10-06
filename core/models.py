# core/models.py

from django.db import models
from django.utils.translation import gettext_lazy as _

# --- النماذج الأساسية ---

class Asset(models.Model):
    ip_address = models.GenericIPAddressField(unique=True, verbose_name=_("IP Address"))
    hostname = models.CharField(max_length=255, blank=True, null=True, verbose_name=_("Hostname"))
    mac_address = models.CharField(max_length=17, blank=True, null=True, verbose_name=_("MAC Address"))
    os = models.CharField(max_length=100, blank=True, null=True, verbose_name=_("Operating System"))
    is_critical = models.BooleanField(default=False, verbose_name=_("Is Critical?"))
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    def __str__(self): return self.hostname or self.ip_address

class Alert(models.Model):
    class Severity(models.TextChoices):
        LOW = 'LOW', _('Low'); MEDIUM = 'MEDIUM', _('Medium'); HIGH = 'HIGH', _('High'); CRITICAL = 'CRITICAL', _('Critical')
    class Status(models.TextChoices):
        NEW = 'NEW', _('New'); IN_PROGRESS = 'IN_PROGRESS', _('In Progress'); RESOLVED = 'RESOLVED', _('Resolved'); FALSE_POSITIVE = 'FALSE_POSITIVE', _('False Positive')
    timestamp = models.DateTimeField(verbose_name=_("Timestamp"))
    description = models.TextField(verbose_name=_("Description"))
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.LOW)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.NEW)
    source_ip = models.GenericIPAddressField(blank=True, null=True)
    destination_ip = models.GenericIPAddressField(blank=True, null=True)
    related_asset = models.ForeignKey(Asset, on_delete=models.SET_NULL, null=True, blank=True)
    source_tool = models.CharField(max_length=100, help_text="e.g., Suricata, Wazuh, Splunk")
    raw_log = models.JSONField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    def __str__(self): return f"{self.severity} Alert from {self.source_tool}"

class IndicatorOfCompromise(models.Model):
    class IOCType(models.TextChoices):
        IP_ADDRESS = 'IP', _('IP Address'); DOMAIN = 'DOMAIN', _('Domain Name'); FILE_HASH = 'HASH', _('File Hash'); URL = 'URL', _('URL')
    ioc_type = models.CharField(max_length=10, choices=IOCType.choices)
    value = models.CharField(max_length=500, unique=True)
    source = models.CharField(max_length=100, blank=True, null=True, help_text="e.g., MISP, VirusTotal")
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    def __str__(self): return f"[{self.ioc_type}] {self.value}"

class Playbook(models.Model):
    name = models.CharField(max_length=200, unique=True); description = models.TextField(blank=True, null=True); is_active = models.BooleanField(default=True)
    def __str__(self): return self.name

class ActionLog(models.Model):
    alert = models.ForeignKey(Alert, on_delete=models.CASCADE, related_name='actions')
    playbook_run = models.ForeignKey(Playbook, on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    details = models.CharField(max_length=500)
    class Meta: ordering = ['-timestamp']
    def __str__(self): return f"Playbook '{self.playbook_run.name}' on Alert #{self.alert.id}"

# --- النماذج الخاصة بالماسح الضوئي (Scanner Framework) ---

class Tool(models.Model):
    name = models.CharField(max_length=100, unique=True, help_text="e.g., Nikto, Nmap, SQLMap")
    description = models.TextField(blank=True, null=True)
    command_template = models.CharField(max_length=500, help_text="e.g., nikto -h {target} -o {output} -format json")
    is_active = models.BooleanField(default=True)
    def __str__(self): return self.name

class Scan(models.Model):
    class Status(models.TextChoices):
        PENDING = 'PENDING', _('Pending'); RUNNING = 'RUNNING', _('Running'); COMPLETED = 'COMPLETED', _('Completed'); FAILED = 'FAILED', _('Failed')
    tool = models.ForeignKey(Tool, on_delete=models.SET_NULL, null=True)
    target_url = models.CharField(max_length=500, verbose_name=_("Target"))
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    task_id = models.CharField(max_length=255, null=True, blank=True, editable=False)
    def __str__(self):
        tool_name = self.tool.name if self.tool else "Unknown"
        return f"{tool_name} scan for {self.target_url} ({self.status})"

class Vulnerability(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name='vulnerabilities')
    description = models.TextField()
    severity = models.CharField(max_length=50)
    cve_id = models.CharField(max_length=50, blank=True, null=True)
    details = models.JSONField()
    
    metasploit_module = models.CharField(max_length=200, blank=True, null=True, help_text="The corresponding Metasploit module name")
    
    def __str__(self): return self.description[:80]