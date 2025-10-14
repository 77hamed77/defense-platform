# network_mapper/models.py
from django.db import models

class NetworkDevice(models.Model):
    ip_address = models.GenericIPAddressField(verbose_name="IP Address")
    mac_address = models.CharField(max_length=17, unique=True, verbose_name="MAC Address")
    hostname = models.CharField(max_length=255, blank=True, null=True, verbose_name="Hostname")
    vendor = models.CharField(max_length=255, blank=True, null=True, verbose_name="Device Vendor")
    
    open_ports = models.JSONField(default=list, blank=True, help_text="List of open ports and services discovered")
    os_details = models.CharField(max_length=500, blank=True, null=True, help_text="Operating System details from Nmap")

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.hostname or self.ip_address

class WirelessNetwork(models.Model):
    bssid = models.CharField(max_length=17, unique=True, verbose_name="BSSID (MAC Address)")
    ssid = models.CharField(max_length=100, verbose_name="Network Name (SSID)")
    encryption_type = models.CharField(max_length=50, blank=True, null=True)
    channel = models.IntegerField(null=True, blank=True)
    signal_strength = models.IntegerField(null=True, blank=True)

    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.ssid or self.bssid