# apk_analyzer/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.apk_analysis_list_view, name='apk_analysis_list'),
    path('<uuid:analysis_id>/', views.apk_analysis_detail_view, name='apk_analysis_detail'),
    path('finding/<int:finding_id>/analyze/', views.analyze_finding_view, name='analyze_apk_finding'),
    path('<uuid:analysis_id>/dynamic/', views.run_dynamic_analysis_view, name='run_dynamic_analysis'),

]