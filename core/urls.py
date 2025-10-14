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

    path('vulnerability/<int:vuln_id>/analyze/', views.analyze_vuln_view, name='analyze_vulnerability'),

    path('scans/<int:scan_id>/eyewitness/', views.run_eyewitness_view, name='run_eyewitness'),
    path('phishing/pages/', views.landing_page_list_view, name='landing_page_list'),
    
    path('phishing/templates/', views.email_template_list_view, name='email_template_list'),
    path('phishing/targets/', views.phishing_target_list_view, name='phishing_target_list'),
    path('phishing/campaigns/', views.phishing_campaign_list_view, name='phishing_campaign_list'),
    
        # --- إضافة جديدة: مسارات التتبع والالتقاط للتصيد ---
    # 1. مسار بكسل التتبع (عند فتح البريد)
    path('track/open/<uuid:result_id>/', views.track_open_view, name='track_open'),
    
    # 2. مسار تتبع النقر على الرابط
    path('track/click/<uuid:result_id>/', views.track_click_view, name='track_click'),
    
    # 3. مسار عرض صفحة الهبوط المزيفة
    path('phish/page/<uuid:result_id>/', views.display_landing_page_view, name='display_landing_page'),

    # 4. مسار استقبال البيانات المدخلة
    path('phish/submit/', views.credential_harvester_view, name='credential_harvester'),
    
    # 5. مسار عرض تفاصيل حملة التصيد
    path('phishing/campaigns/<int:campaign_id>/', views.phishing_campaign_detail_view, name='phishing_campaign_detail'),

    # 6. مسار عرض الأدلة المجمعة (مثل لقطات الشاشة، بيانات الاعتماد)
    path('phish/evidence/<uuid:result_id>/', views.evidence_harvester_view, name='evidence_harvester'),
]