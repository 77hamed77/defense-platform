# core/views.py
from urllib.parse import urlparse
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.db.models import Count
from .models import Alert, Asset, IndicatorOfCompromise, Playbook, ActionLog
from rest_framework import generics
from .serializers import AlertSerializer
from .filters import AlertFilter
from django.core.paginator import Paginator
from rest_framework_api_key.permissions import HasAPIKey
from datetime import datetime, timezone
import subprocess
import json
from django.shortcuts import render, redirect
from django.utils import timezone
from .models import Scan, Vulnerability
from django.contrib import messages
import csv 
from .tasks import execute_scan_task # <-- استيراد المهمة الجديدة
from .serializers import AlertSerializer, ScanStatusSerializer # <-- أضف ScanStatusSerializer
from rest_framework.permissions import IsAuthenticated # <-- سنقوم بتأمينه للمستخدمين المسجلين فقط
from .tasks import enrich_ip_with_virustotal
import os
from django.http import JsonResponse, Http404
from .models import Tool
from .tasks import execute_scan_task
from defense_platform.celery import app as celery_app
from .tasks import execute_scan_task, enrich_ip_with_virustotal, run_metasploit_exploit # <-- أضف المهمة الجديدة


def dashboard(request):
    latest_alerts = Alert.objects.order_by('-timestamp')[:10]
    
    total_alerts = Alert.objects.count()
    total_assets = Asset.objects.count()
    total_iocs = IndicatorOfCompromise.objects.count()

    # --- إضافة جديدة: تجهيز بيانات الرسم البياني ---
    # تجميع التنبيهات حسب الخطورة وحساب عدد كل منها
    severity_counts_query = Alert.objects.values('severity').annotate(count=Count('severity')).order_by('severity')
    
    # استخراج العناوين والبيانات من نتيجة الاستعلام
    severity_labels = [item['severity'] for item in severity_counts_query]
    severity_data = [item['count'] for item in severity_counts_query]
    # ----------------------------------------------

    context = {
        'latest_alerts': latest_alerts,
        'total_alerts': total_alerts,
        'total_assets': total_assets,
        'total_iocs': total_iocs,
        'severity_labels': severity_labels,  # <-- تمرير العناوين
        'severity_data': severity_data,      # <-- تمرير البيانات
    }
    
    return render(request, 'core/dashboard.html', context)

class AlertCreateAPIView(generics.CreateAPIView):
    queryset = Alert.objects.all()
    serializer_class = AlertSerializer
    permission_classes = [HasAPIKey] 
    def perform_create(self, serializer):
        """
        Custom logic to perform before creating a new Alert.
        This is where we'll add our IOC correlation logic.
        """
        source_ip = serializer.validated_data.get('source_ip')
        description = serializer.validated_data.get('description', '')

        # 1. التحقق من وجود IP المصدر في قائمة IOCs النشطة
        if source_ip and IndicatorOfCompromise.objects.filter(value=source_ip, ioc_type='IP', is_active=True).exists():
            # 2. إذا تم العثور على تطابق، قم بتعزيز التنبيه
            #    - ارفع الخطورة إلى CRITICAL
            #    - أضف علامة مميزة إلى الوصف
            serializer.validated_data['severity'] = 'CRITICAL'
            serializer.validated_data['description'] = f"[IOC MATCH FOUND] {description}"
            
            # يمكنك هنا إضافة المزيد من الإجراءات، مثل إرسال إشعار فوري
        
        # 3. احفظ التنبيه (سواء تم تعديله أم لا)
        serializer.save()

def alert_detail(request, pk):
    alert = get_object_or_404(Alert, pk=pk)
    if request.method == 'POST':
        new_status = request.POST.get('status')
        if new_status in [status[0] for status in Alert.Status.choices]:
            alert.status = new_status
            alert.save()
            return redirect('alert-detail', pk=alert.pk) # إعادة تحميل الصفحة لإظهار التغيير
    context = {
        'alert': alert,
        'status_choices': Alert.Status.choices,
        'playbooks': Playbook.objects.filter(is_active=True) # <-- أضف هذا
    }
    return render(request, 'core/alert_detail.html', context)

def create_ioc_from_alert(request, pk):
    # هذا العرض يقبل طلبات POST فقط للأمان
    if request.method == 'POST':
        alert = get_object_or_404(Alert, pk=pk)
        source_ip = alert.source_ip

        if source_ip:
            # get_or_create: محاولة جلب IOC بنفس الـ IP، إذا لم يكن موجودًا، قم بإنشائه
            # created: متغير منطقي (True/False) يخبرنا إذا تم إنشاء كائن جديد
            ioc, created = IndicatorOfCompromise.objects.get_or_create(
                value=source_ip,
                defaults={'ioc_type': 'IP'}
            )

            if created:
                messages.success(request, f"IOC for IP address {source_ip} created successfully!")
            else:
                messages.warning(request, f"IOC for IP address {source_ip} already exists.")
            
            # تحديث حالة التنبيه للإشارة إلى أنه تم اتخاذ إجراء
            alert.status = 'IN_PROGRESS'
            alert.save()

        else:
            messages.error(request, "Alert does not have a source IP address.")

    # في كل الحالات، قم بإعادة توجيه المستخدم إلى نفس صفحة التفاصيل
    return redirect('alert-detail', pk=pk)

def ioc_list(request):
    # جلب كل مؤشرات الاختراق، مرتبة من الأحدث إلى الأقدم
    all_iocs = IndicatorOfCompromise.objects.all().order_by('-first_seen')

    context = {
        'iocs': all_iocs
    }
    return render(request, 'core/ioc_list.html', context)

def hunting_view(request):
    # نقوم بتمرير queryset الأصلي أولاً
    alert_list = Alert.objects.all().order_by('-timestamp')
    alert_filter = AlertFilter(request.GET, queryset=alert_list)
    
    # الحصول على عدد النتائج قبل الترقيم
    results_count = alert_filter.qs.count()

    # إعداد الترقيم
    paginator = Paginator(alert_filter.qs, 15) # عرض 15 نتيجة في كل صفحة
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'filter': alert_filter,
        'page_obj': page_obj, # تمرير كائن الصفحة إلى القالب
        'results_count': results_count,
    }
    return render(request, 'core/hunting.html', context)

def run_playbook(request, alert_pk, playbook_pk):
    """
    Handles the execution of a selected playbook on a specific alert.
    """
    # نتأكد أن الطلب هو POST للأمان، لمنع تشغيل الإجراءات عبر طلب GET
    if request.method != 'POST':
        return redirect('alert-detail', pk=alert_pk)

    # جلب الكائنات المطلوبة من قاعدة البيانات، مع معالجة خطأ 404 إذا لم تكن موجودة
    alert = get_object_or_404(Alert, pk=alert_pk)
    playbook = get_object_or_404(Playbook, pk=playbook_pk)
    
    # --- المنطق الرئيسي لتحديد أي Playbook سيتم تشغيله بناءً على اسمه ---

    # 1. Playbook: الاحتواء الأولي للتهديد (متزامن وسريع)
    if playbook.name == 'Initial Threat Containment':
        source_ip = alert.source_ip
        if source_ip:
            # إنشاء IOC وتحديث حالة التنبيه
            ioc, created = IndicatorOfCompromise.objects.get_or_create(
                value=source_ip, 
                defaults={'ioc_type': 'IP', 'source': 'Playbook Action'}
            )
            alert.status = 'IN_PROGRESS'
            alert.save()

            # تسجيل تفاصيل ما حدث في سجل الإجراءات
            details = f"Successfully ran playbook. IOC for {source_ip} was {'created' if created else 'already existed'}. Alert status set to In Progress."
            ActionLog.objects.create(alert=alert, playbook_run=playbook, details=details)
            messages.success(request, "Playbook 'Initial Threat Containment' executed successfully.")
        else:
            messages.error(request, "Playbook failed: Alert has no source IP address.")

    # 2. Playbook: التحليل المعمق للـ IP (غير متزامن وبطيء)
    elif playbook.name == 'Deep IP Analysis':
        if not alert.source_ip:
            messages.error(request, "Playbook failed: Alert has no source IP.")
        else:
            # استدعاء مهمة Celery لتنفيذها في الخلفية
            # نمرر فقط الـ IDs، وهي أفضل ممارسة
            enrich_ip_with_virustotal.delay(alert.id, playbook.id)
            
            # إعطاء رد فوري للمستخدم
            messages.success(request, "Playbook 'Deep IP Analysis' has been scheduled. Results will appear in the Action Log shortly.")
    
    # 3. معالجة أي Playbook آخر غير معرف
    else:
        messages.warning(request, f"Playbook '{playbook.name}' is defined but not implemented yet.")
        
    # في كل الحالات، قم بإعادة توجيه المستخدم إلى نفس صفحة التفاصيل
    return redirect('alert-detail', pk=alert_pk)

def honeypot_api(request):
    """
    This view acts as a simple honeypot. Any access attempt is logged 
    as a critical alert, and an IOC is created from the source IP.
    """
    # 1. استخراج عنوان IP الخاص بالمهاجم
    #    نستخدم X-Forwarded-For للمرونة خلف بروكسي، مع الرجوع إلى REMOTE_ADDR
    ip_address = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR'))
    
    if ip_address:
        # 2. إنشاء تنبيه بخطورة حرجة
        description = f"[HONEYPOT] Unauthorized access attempt on deprecated API endpoint: /api/v1/user/login"
        alert = Alert.objects.create(
            timestamp=datetime.now(timezone.utc),
            description=description,
            severity='CRITICAL',
            source_ip=ip_address,
            source_tool='Deception Layer',
            status='NEW',
            raw_log={
                'user_agent': request.META.get('HTTP_USER_AGENT'),
                'method': request.method,
                'headers': dict(request.headers),
            }
        )
        
        # 3. إنشاء IOC من عنوان IP تلقائيًا
        IndicatorOfCompromise.objects.get_or_create(
            value=ip_address,
            defaults={'ioc_type': 'IP', 'source': 'Internal Honeypot'}
        )
        
        # يمكنك هنا إضافة إجراءات إضافية، مثل إرسال إشعار فوري
        
    # 4. الرد على المهاجم برسالة غامضة وناجحة ظاهريًا لخداعه
    return JsonResponse({'status': 'success', 'message': 'Login successful'}, status=200)

def scanner_view(request):
    if request.method == 'POST':
        url_input = request.POST.get('url', '').strip()
        tool_id = request.POST.get('tool')

        if not url_input or not tool_id:
            messages.error(request, "Please provide a target and select a tool.")
            return redirect('scanner')
        
        try:
            tool = Tool.objects.get(id=tool_id)
        except Tool.DoesNotExist:
            messages.error(request, "Selected tool not found.")
            return redirect('scanner')

        # --- منطق ذكي لتحضير الهدف ---
        target = url_input
        if tool.name == 'Nmap':
            # Nmap يريد اسم نطاق فقط، لذلك نزيل البروتوكول والمسارات
            parsed_uri = urlparse(url_input)
            target = parsed_uri.netloc or parsed_uri.path
            # إزالة البورت إذا كان موجودًا
            if ':' in target:
                target = target.split(':')[0]
        # --------------------------------

        scan = Scan.objects.create(target_url=target, tool=tool, status='PENDING')
        async_result = execute_scan_task.delay(scan.id)
        scan.task_id = async_result.id
        scan.save()
        
        messages.success(request, f"{tool.name} scan for {target} has been scheduled.")
        return redirect('scanner')

    scans_history = Scan.objects.order_by('-created_at')[:5]
    available_tools = Tool.objects.filter(is_active=True)
    context = {
        'scans_history': scans_history,
        'available_tools': available_tools,
    }
    return render(request, 'core/scanner.html', context)

class ScanStatusAPIView(generics.RetrieveAPIView):
    queryset = Scan.objects.all()
    serializer_class = ScanStatusSerializer
    # تأمين بسيط: فقط المستخدمون المسجلون يمكنهم التحقق من الحالة
    # يمكنك إنشاء صلاحيات أكثر تعقيدًا لاحقًا
    permission_classes = [IsAuthenticated]
    

def scan_detail_view(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    vulnerabilities = Vulnerability.objects.filter(scan=scan)
    context = {
        "scan": scan,
        "vulnerabilities": vulnerabilities
    }
    return render(request, "core/scan_detail.html", context)

def scan_status_api(request, scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        raise Http404("Scan not found")

    return JsonResponse({
        "id": scan.id,
        "status": scan.status,
        "get_status_display": scan.get_status_display(),
        "created_at": scan.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "completed_at": scan.completed_at.strftime("%Y-%m-%d %H:%M:%S") if scan.completed_at else None,
        "vulnerabilities_count": scan.vulnerabilities.count(),
    })

def stop_scan_view(request, scan_id):
    if request.method == 'POST':
        scan = get_object_or_404(Scan, id=scan_id)
        if scan.task_id and (scan.status == 'RUNNING' or scan.status == 'PENDING'):
            # إرسال إشارة لإلغاء المهمة وقتلها
            celery_app.control.revoke(scan.task_id, terminate=True, signal='SIGKILL')
            
            # تحديث الحالة يدويًا
            scan.status = 'FAILED'
            scan.completed_at = timezone.now()
            scan.save()
            
            messages.warning(request, f"Scan for {scan.target_url} has been terminated.")
        else:
            messages.error(request, "This scan is already completed or cannot be stopped.")
    
    return redirect('scanner')

def exploit_view(request, vuln_id):
    if request.method == 'POST':
        vuln = get_object_or_404(Vulnerability, id=vuln_id)
        if vuln.metasploit_module and vuln.scan.target_url:
            # استدعاء مهمة Celery لتنفيذ الاستغلال في الخلفية
            run_metasploit_exploit.delay(vuln.id)
            messages.success(request, f"Metasploit exploit '{vuln.metasploit_module}' has been scheduled against {vuln.scan.target_url}.")
        else:
            messages.error(request, "This vulnerability has no associated Metasploit module or target.")
    
    # أعد التوجيه إلى صفحة تفاصيل الفحص
    return redirect('scan_detail', scan_id=vuln.scan.id)