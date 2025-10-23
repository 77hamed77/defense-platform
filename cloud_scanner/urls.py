# cloud_scanner/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # المسار الرئيسي لعرض قائمة بيئات السحابة وبدء الفحص
    path('', views.cloud_dashboard_view, name='cloud_dashboard'),
    # المسار لعرض تقرير فحص معين
    path('scans/<uuid:scan_id>/', views.cloud_scan_detail_view, name='cloud_scan_detail'),
    
    path('start-scan/<int:env_id>/', views.start_cloud_scan_view, name='start_cloud_scan'),

]