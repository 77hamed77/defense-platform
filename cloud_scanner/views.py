# cloud_scanner/views.py
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import AWSEnvironment, CloudScan
from core.tasks import run_prowler_audit_task # <-- سننشئ هذه المهمة
from .models import CloudScan # تأكد من وجود هذا الاستيراد
from django.shortcuts import render, get_object_or_404
from django.db.models import Count

def cloud_dashboard_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        access_key = request.POST.get('access_key_id')
        secret_key = request.POST.get('secret_access_key')
        region = request.POST.get('default_region')

        if name and access_key and secret_key and region:
            AWSEnvironment.objects.create(
                name=name,
                access_key_id=access_key,
                secret_access_key=secret_key,
                default_region=region
            )
            messages.success(request, f"AWS Environment '{name}' added successfully.")
            return redirect('cloud_dashboard')
        else:
            messages.error(request, "Please fill out all fields.")

    environments = AWSEnvironment.objects.all()
    scans = CloudScan.objects.all().order_by('-created_at')[:10]
    context = {
        'environments': environments,
        'scans': scans,
    }
    return render(request, 'cloud_scanner/cloud_dashboard.html', context)

def start_cloud_scan_view(request, env_id): # <-- دالة جديدة
    if request.method == 'POST':
        try:
            environment = AWSEnvironment.objects.get(id=env_id)
            scan = CloudScan.objects.create(environment=environment, status='PENDING')
            run_prowler_audit_task.delay(scan.id)
            messages.success(request, f"Prowler audit for '{environment.name}' has been scheduled.")
        except AWSEnvironment.DoesNotExist:
            messages.error(request, "AWS Environment not found.")
    return redirect('cloud_dashboard')


def cloud_scan_detail_view(request, scan_id):
    """
    يعرض تقريرًا مفصلاً لنتائج فحص Prowler، مع إحصائيات ورسوم بيانية.
    """
    scan = get_object_or_404(CloudScan, id=scan_id)
    findings = scan.findings.all()

    # --- تجميع البيانات للرسوم البيانية ---
    
    # 1. توزيع الاكتشافات حسب الخطورة
    severity_distribution = findings.values('severity').annotate(count=Count('severity')).order_by('severity')
    
    # 2. توزيع الاكتشافات حسب خدمة AWS
    service_distribution = findings.values('service_name').annotate(count=Count('service_name')).order_by('-count')[:10] # أعلى 10 خدمات

    context = {
        'scan': scan,
        'findings': findings,
        'total_findings': findings.count(),
        
        # تمرير بيانات الرسوم البيانية
        'severity_distribution': list(severity_distribution),
        'service_distribution': list(service_distribution),
    }
    return render(request, 'cloud_scanner/cloud_scan_detail.html', context)