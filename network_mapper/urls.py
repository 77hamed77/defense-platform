# network_mapper/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.network_map_view, name='network_map'),
    path('start-scan/', views.start_network_scan_view, name='start_network_scan'),
    path('device/<int:device_id>/audit/', views.audit_device_view, name='audit_device'),
    
]