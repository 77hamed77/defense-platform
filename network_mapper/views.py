# network_mapper/views.py
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import NetworkDevice
from core.models import Tool
from core.tasks import run_network_discovery_task # <-- سننشئ هذه المهمة
from celery.result import AsyncResult
from django.utils import timezone
from core.tasks import run_routersploit_audit # <-- استيراد المهمة الجديدة

def network_map_view(request):
    """
    يعرض خريطة الأجهزة، ويتحقق مما إذا كانت هناك مهمة اكتشاف نشطة.
    """
    devices = NetworkDevice.objects.all().order_by('ip_address')
    
    # --- إضافة جديدة: التحقق من وجود مهمة نشطة ---
    is_scan_active = False
    # (هذه طريقة بسيطة. في نظام حقيقي، ستحتاج إلى طريقة أكثر قوة لتتبع المهام)
    # لنفترض أننا نريد التحقق مما إذا تم تشغيل فحص في آخر دقيقتين
    from django.utils import timezone
    from datetime import timedelta
    if 'last_scan_start_time' in request.session:
        last_start = request.session['last_scan_start_time']
        # تحويل السلسلة النصية مرة أخرى إلى كائن datetime
        last_start_dt = timezone.datetime.fromisoformat(last_start)
        if timezone.now() - last_start_dt < timedelta(minutes=2):
            is_scan_active = True

    context = {
        'devices': devices,
        'is_scan_active': is_scan_active, # <-- تمرير الحالة إلى القالب
    }
    return render(request, 'network_mapper/network_map.html', context)

def start_network_scan_view(request):
    """
    يقرأ نطاق IP والواجهة من النموذج ويبدأ مهمة فحص الشبكة.
    """
    if request.method == 'POST':
        # قراءة البيانات مباشرة من النموذج
        ip_range = request.POST.get('ip_range')
        interface = request.POST.get('interface')

        # التحقق من أن المدخلات ليست فارغة
        if not ip_range or not interface:
            messages.error(request, "Both IP range and interface are required to start a scan.")
            return redirect('network_map')
        
        # لا نحتاج إلى نموذج Tool هنا، بل نستدعي المهمة مباشرة
        run_network_discovery_task.delay(ip_range, interface)
        messages.success(request, f"Network discovery for range {ip_range} on interface {interface} has been scheduled.")
    
         # --- إضافة جديدة: حفظ وقت البدء في الـ session ---
        request.session['last_scan_start_time'] = timezone.now().isoformat()
        
    return redirect('network_map')


def audit_device_view(request, device_id):
    if request.method == 'POST':
        try:
            device = NetworkDevice.objects.get(id=device_id)
            run_routersploit_audit.delay(device.id)
            messages.success(request, f"RouterSploit audit has been scheduled for {device.ip_address}.")
        except NetworkDevice.DoesNotExist:
            messages.error(request, "Device not found.")
    
    return redirect('network_map')