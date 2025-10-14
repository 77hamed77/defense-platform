# vulnerable_app/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('xxe-lab/', views.xxe_vulnerable_endpoint, name='xxe_lab'),
]