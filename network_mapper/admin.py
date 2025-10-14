# network_mapper/admin.py
from django.contrib import admin
from .models import NetworkDevice, WirelessNetwork

admin.site.register(NetworkDevice)
admin.site.register(WirelessNetwork)