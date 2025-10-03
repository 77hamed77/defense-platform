# defense_platform/urls.py

from django.contrib import admin
from django.urls import path, include  # <-- تأكد من إضافة 'include'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('core.urls')),  # <-- أضف هذا السطر
]