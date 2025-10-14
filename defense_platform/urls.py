# defense_platform/urls.py

from django.contrib import admin
from django.urls import path, include  # <-- تأكد من إضافة 'include'
from django.conf import settings
from django.conf.urls.static import static


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('core.urls')),  
    path('lab/', include('vulnerable_app.urls')),
    path('network/', include('network_mapper.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)