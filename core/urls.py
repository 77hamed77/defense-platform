# core/urls.py

from django.urls import path
from . import views

urlpatterns = [
    # مسار واجهة الويب
    path('', views.dashboard, name='dashboard'),
    
    # مسار واجهة الـ API (عادة ما يوضع تحت بادئة /api/)
    path('api/alerts/', views.AlertCreateAPIView.as_view(), name='alert-create'),
    # المسار سيقبل رقمًا صحيحًا (ID التنبيه) ويعرض صفحته
    path('alert/<int:pk>/', views.alert_detail, name='alert-detail'),
    # هذا المسار مخصص لتنفيذ إجراء إنشاء IOC من تنبيه
    path('alert/<int:pk>/create-ioc/', views.create_ioc_from_alert, name='alert-create-ioc'),
    path('iocs/', views.ioc_list, name='ioc-list'),
    path('hunting/', views.hunting_view, name='hunting'),
    path('alert/<int:alert_pk>/run-playbook/<int:playbook_pk>/', views.run_playbook, name='run-playbook'),
    path('api/v1/user/login', views.honeypot_api, name='honeypot-api'),
    path('scanner/', views.scanner_view, name='scanner'),
    path('api/scans/<int:pk>/status/', views.ScanStatusAPIView.as_view(), name='scan-status-api'),
    path("api/scans/<int:scan_id>/status/", views.scan_status_api, name="scan_status_api"),
    
    path("scans/<int:scan_id>/", views.scan_detail_view, name="scan_detail"),
    path('scans/<int:scan_id>/stop/', views.stop_scan_view, name='stop_scan'),
    
    path('vulnerability/<int:vuln_id>/exploit/', views.exploit_view, name='test_exploit'),

    
]