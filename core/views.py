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
from .tasks import enrich_ip_with_virustotal , run_eyewitness_on_scan
import os
from django.http import JsonResponse, Http404
from .models import Tool
from .tasks import execute_scan_task
from defense_platform.celery import app as celery_app
from .tasks import execute_scan_task, enrich_ip_with_virustotal, run_metasploit_exploit, analyze_vulnerability_with_ai # <-- أضف المهمة الجديدة
from .tasks import execute_scan_task, run_recon_and_attack_playbook # <-- أضف المهمة الجديدة
import uuid
from .models import LandingPage # <-- أضف هذا
from .tasks import clone_landing_page
from .models import EmailTemplate
from .models import PhishingTarget
from .models import PhishingCampaign, EmailTemplate, LandingPage, PhishingTarget
from .tasks import launch_phishing_campaign # <-- سننشئ هذه المهمة لاحقًا
from django.http import HttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from .models import PhishingResult, Alert
from django.db.models import Count
import base64
from django.core.files.base import ContentFile
from django.conf import settings
import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from celery import shared_task
from .models import LandingPage
from django.db.models import F, ExpressionWrapper, DurationField
import json
import base64
import os
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.files.base import ContentFile
from django.conf import settings
from .models import PhishingResult
from django.shortcuts import render, get_object_or_404
from django.db.models import F, ExpressionWrapper, DurationField, Avg
from .models import PhishingCampaign
from django.shortcuts import render, redirect
from django.contrib import messages
from .models import PhishingCampaign, EmailTemplate, LandingPage, PhishingTarget
from .tasks import launch_phishing_campaign # <-- استيراد المهمة
from .models import Alert, IndicatorOfCompromise, Scan, Vulnerability
from network_mapper.models import NetworkDevice
from apk_analyzer.models import APKAnalysis
from cloud_scanner.models import CloudScan
from .models import Alert, IndicatorOfCompromise, Scan, Vulnerability, PhishingCampaign
from network_mapper.models import NetworkDevice
from apk_analyzer.models import APKAnalysis
from cloud_scanner.models import CloudScan
from django.shortcuts import render
from django.db.models import Count, Q
from .models import Alert, Vulnerability, Scan, PhishingCampaign
from network_mapper.models import NetworkDevice
from apk_analyzer.models import APKAnalysis
from cloud_scanner.models import CloudScan

def dashboard(request):
    """
    تجمع البيانات من جميع وحدات المنصة لعرضها في لوحة التحكم الرئيسية.
    """
    # --- قسم التنبيهات (Alerts) ---
    latest_alerts = Alert.objects.order_by('-timestamp')[:5]
    critical_alerts_count = Alert.objects.filter(severity='CRITICAL', status='NEW').count()

    # --- قسم الشبكة (Network) ---
    total_devices = NetworkDevice.objects.count()
    latest_devices = NetworkDevice.objects.order_by('-last_seen')[:5]

    # --- قسم الفحص (Scanning) ---
    latest_scans = Scan.objects.order_by('-created_at')[:5]
    total_vulnerabilities = Vulnerability.objects.count()

    # --- قسم تحليل APK ---
    latest_apk_analyses = APKAnalysis.objects.order_by('-created_at')[:5]

    # --- قسم السحابة (Cloud) ---
    latest_cloud_scans = CloudScan.objects.order_by('-created_at')[:5]
    
    # --- قسم التصيد الاحتيالي (Phishing) ---
    # نستخدم annotate لإضافة عدد النقرات والبيانات المدخلة لكل حملة بكفاءة
    latest_phishing_campaigns = PhishingCampaign.objects.annotate(
        clicked_count=Count('results', filter=Q(results__is_clicked=True)),
        submitted_count=Count('results', filter=Q(results__submitted_data=True))
    ).order_by('-created_at')[:5]

    # --- تجميع كل البيانات لتمريرها إلى القالب ---
    context = {
        'latest_alerts': latest_alerts,
        'critical_alerts_count': critical_alerts_count,
        'total_devices': total_devices,
        'latest_devices': latest_devices,
        'latest_scans': latest_scans,
        'total_vulnerabilities': total_vulnerabilities,
        'latest_apk_analyses': latest_apk_analyses,
        'latest_cloud_scans': latest_cloud_scans,
        'latest_phishing_campaigns': latest_phishing_campaigns,
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
    """
    يعالج طلبات بدء الفحص (للأدوات الفردية والـ Playbooks)،
    ويعرض واجهة الماسح الضوئي مع سجل آخر عمليات الفحص.
    """
    if request.method == 'POST':
        tool_id = request.POST.get('tool')
        
        try:
            tool = Tool.objects.get(id=tool_id)
        except (Tool.DoesNotExist, ValueError):
            messages.error(request, "Invalid tool selected.")
            return redirect('scanner')

        # --- المنطق الرئيسي: التفريق بين Playbook والأدوات الأخرى ---

        if 'Playbook' in tool.name:
            # -- منطق تشغيل الـ Playbook --
            url_input = request.POST.get('url', '').strip()
            if not url_input:
                messages.error(request, "A target domain is required for playbooks.")
                return redirect('scanner')

            scan = Scan.objects.create(
                target_url=url_input, 
                tool=tool, 
                status='PENDING',
                is_playbook_scan=True
            )
            
            if tool.name == 'Playbook: Recon & Attack':
                async_result = run_recon_and_attack_playbook.delay(scan.id)
                scan.task_id = async_result.id
                scan.save()
                messages.success(request, f"Playbook 'Recon & Attack' for {url_input} has been scheduled.")
            
            # يمكنك إضافة playbooks أخرى هنا في المستقبل
            # elif tool.name == 'Playbook: ...':
            
        else:
            # -- منطق تشغيل أداة فردية --
            
            target_for_db = ""
            target_for_tool = ""

            if tool.name == 'XXEinjector':
                raw_request = request.POST.get('xxe_request', '').strip()
                if not raw_request:
                    messages.error(request, "Raw HTTP request is required for XXEinjector.")
                    return redirect('scanner')
                
                host_line = next((line for line in raw_request.split('\n') if line.lower().startswith('host:')), None)
                target_for_db = host_line.split(':')[1].strip() if host_line else "XXE Request"

                temp_filename = f"/tmp/xxe_req_{uuid.uuid4()}.txt"
                with open(temp_filename, 'w') as f:
                    f.write(raw_request)
                
                target_for_tool = temp_filename
            
            else:
                url_input = request.POST.get('url', '').strip()
                if not url_input:
                    messages.error(request, "A target URL or domain is required.")
                    return redirect('scanner')
                
                target_for_db = url_input
                target_for_tool = url_input
                
                if tool.name in ['Nmap', 'Subfinder', 'Amass']:
                    parsed_uri = urlparse(url_input)
                    target_for_tool = parsed_uri.netloc or parsed_uri.path
                    if ':' in target_for_tool:
                        target_for_tool = target_for_tool.split(':')[0]

            # إنشاء سجل الفحص واستدعاء المهمة العامة
            scan = Scan.objects.create(target_url=target_for_db, tool=tool, status='PENDING')
            async_result = execute_scan_task.delay(scan.id, target_for_tool)
            scan.task_id = async_result.id
            scan.save()
            
            messages.success(request, f"{tool.name} scan for {target_for_db} has been scheduled.")
        
        return redirect('scanner')

    # --- منطق عرض الصفحة (GET request) ---
    scans_history = Scan.objects.order_by('-created_at')[:15]
    available_tools = Tool.objects.filter(is_active=True).order_by('name')
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
        if vuln.scan.target_url:
            # استدعاء مهمة Celery لتنفيذ الاستغلال في الخلفية
            run_metasploit_exploit.delay(vuln.id)
            messages.success(request, f"Metasploit exploit '{vuln.metasploit_module}' has been scheduled against {vuln.scan.target_url}.")
        else:
            messages.error(request, "This vulnerability has no associated Metasploit module or target.")
    
    # أعد التوجيه إلى صفحة تفاصيل الفحص
    return redirect('scan_detail', scan_id=vuln.scan.id)

def analyze_vuln_view(request, vuln_id):
    if request.method == 'POST':
        vuln = get_object_or_404(Vulnerability, id=vuln_id)
        
        # استدعاء المهمة في الخلفية
        analyze_vulnerability_with_ai.delay(vuln.id)
        
        messages.success(request, "AI analysis has been scheduled. The report will appear below shortly.")
    
    return redirect('scan_detail', scan_id=vuln.scan.id)


def run_eyewitness_view(request, scan_id):
    if request.method == 'POST':
        scan = get_object_or_404(Scan, id=scan_id)
        run_eyewitness_on_scan.delay(scan.id)
        messages.success(request, "Eyewitness scan has been scheduled. The report link will appear on this page once completed.")
    return redirect('scan_detail', scan_id=scan_id)



def landing_page_list_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        url_to_clone = request.POST.get('url_to_clone')

        if name and url_to_clone:
            # إنشاء سجل أولي في قاعدة البيانات
            page = LandingPage.objects.create(name=name, html_content="Cloning in progress...")
            # استدعاء مهمة Celery للقيام بالعمل الشاق
            clone_landing_page.delay(page.id, url_to_clone)
            messages.success(request, f"Cloning for '{name}' has been scheduled. The page will be ready shortly.")
            return redirect('landing_page_list')
        else:
            messages.error(request, "Both a name and a URL are required.")

    pages = LandingPage.objects.all().order_by('-created_at')
    context = {'pages': pages}
    return render(request, 'core/landing_page_list.html', context)

def email_template_list_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        subject = request.POST.get('subject')
        body = request.POST.get('body')
        telegram_message = request.POST.get('telegram_message') # <-- إضافة جديدة


        if name and subject and body:
            EmailTemplate.objects.create(name=name, subject=subject, body=body , telegram_message=telegram_message) # <-- إضافة جديدة
            messages.success(request, f"Email template '{name}' created successfully.")
            return redirect('email_template_list')
        else:
            messages.error(request, "All fields are required.")

    templates = EmailTemplate.objects.all().order_by('-created_at')
    context = {'templates': templates}
    return render(request, 'core/email_template_list.html', context)


def phishing_target_list_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        telegram_id = request.POST.get('telegram_id') # <-- إضافة جديدة


        if email:
            # get_or_create لمنع إضافة نفس البريد مرتين
            target, created = PhishingTarget.objects.get_or_create(
                email=email, 
                defaults={'name': name, 'telegram_user_id': telegram_id} # <-- إضافة جديدة
            )
            if created:
                messages.success(request, f"Target '{email}' added successfully.")
            else:
                messages.warning(request, f"Target '{email}' already exists.")
            return redirect('phishing_target_list')
        else:
            messages.error(request, "Email address is required.")

    targets = PhishingTarget.objects.all().order_by('-created_at')
    context = {'targets': targets}
    return render(request, 'core/phishing_target_list.html', context)

def phishing_campaign_list_view(request):
    """
    يعالج إنشاء وعرض حملات التصيد الاحتيالي.
    """
    if request.method == 'POST':
        # استخلاص البيانات من النموذج
        name = request.POST.get('name')
        template_id = request.POST.get('email_template')
        page_id = request.POST.get('landing_page')
        target_ids = request.POST.getlist('targets') # getlist للحصول على كل الأهداف المحددة
        launch_date_str = request.POST.get('launch_date')

        # التحقق من أن كل الحقول المطلوبة موجودة
        if name and template_id and page_id and target_ids and launch_date_str:
            try:
                # 1. إنشاء الحملة وربطها بالكائنات الأخرى
                campaign = PhishingCampaign.objects.create(
                    name=name,
                    email_template_id=template_id,
                    landing_page_id=page_id,
                    launch_date=launch_date_str,
                    status='SCHEDULED' # تعيين الحالة الأولية
                )
                launch_phishing_campaign.delay(campaign.id)
                # ربط الأهداف المحددة بالحملة
                campaign.targets.set(target_ids)
                
                # 2. استدعاء مهمة Celery لتنفيذ الحملة في الخلفية
                #    (يمكن تعديل هذا لاحقًا ليتم الإطلاق في launch_date المحدد)
                launch_phishing_campaign.delay(campaign.id)
                
                messages.success(request, f"Campaign '{name}' has been prepared. Check the Celery worker log to get the unique links for manual sending.")
                
            except Exception as e:
                messages.error(request, f"Failed to create campaign due to an error: {e}")
        else:
            messages.error(request, "Please fill out all required fields to create a campaign.")

        # في حالة وجود خطأ، نعيد عرض الصفحة مع البيانات التي أدخلها المستخدم (لتحسين التجربة)
        # (هذا الجزء يمكن تحسينه باستخدام Django Forms لاحقًا)

    # --- منطق عرض الصفحة (GET request) ---
    
    # جلب كل الحملات لعرضها في الجدول
    campaigns = PhishingCampaign.objects.all().order_by('-created_at')
    
    # جلب كل الخيارات المتاحة لملء القوائم المنسدلة في النموذج
    available_templates = EmailTemplate.objects.all()
    available_pages = LandingPage.objects.all()
    available_targets = PhishingTarget.objects.all()

    context = {
        'campaigns': campaigns,
        'available_templates': available_templates,
        'available_pages': available_pages,
        'available_targets': available_targets,
    }
    return render(request, 'core/phishing_campaign_list.html', context)

# --- إضافة جديدة: الدوال الخاصة ببوابات التتبع ---

def track_open_view(request, result_id):
    """
    يسجل أن البريد الإلكتروني قد تم فتحه.
    يرجع صورة شفافة بحجم 1x1 بكسل.
    """
    try:
        result = PhishingResult.objects.get(unique_id=result_id)
        if not result.is_opened:
            result.is_opened = True
            result.opened_date = timezone.now()
            result.save()
    except PhishingResult.DoesNotExist:
        pass # نتجاهل الأخطاء بصمت
    
    # إرجاع صورة GIF شفافة
    pixel = b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
    return HttpResponse(pixel, content_type='image/gif')

def track_click_view(request, result_id):
    """
    يسجل أن الرابط قد تم النقر عليه، ثم يعيد توجيه المستخدم إلى صفحة الهبوط.
    """
    try:
        result = PhishingResult.objects.get(unique_id=result_id)
        if not result.is_clicked:
            result.is_clicked = True
            result.clicked_date = timezone.now()
            result.save()
        
        # إعادة التوجيه إلى صفحة الهبوط المزيفة
        return redirect('display_landing_page', result_id=result.unique_id)
    except PhishingResult.DoesNotExist:
        # إذا كان الرابط غير صالح، أعد التوجيه إلى صفحة آمنة
        return redirect('https://www.google.com')

def display_landing_page_view(request, result_id):
    """
    يعرض محتوى صفحة الهبوط المزيفة.
    """
    result = get_object_or_404(PhishingResult, unique_id=result_id)
    html_content = result.campaign.landing_page.html_content
    # يمكنك هنا إضافة منطق لتضمين result_id في النموذج كحقل مخفي
    # ولكن للتبسيط، سنعتمد على أن المتصفح سيحفظ الـ "referer"
    return HttpResponse(html_content)

@csrf_exempt # تعطيل حماية CSRF فقط لهذا الـ View لأنه يستقبل بيانات من الخارج
def credential_harvester_view(request):
    """
    يلتقط البيانات المرسلة من صفحة الهبوط المزيفة.
    """
    if request.method == 'POST':
        # استخراج الـ unique_id من رابط "referer" (الرابط الذي أتى منه المستخدم)
        referer = request.META.get('HTTP_REFERER')
        try:
            # استخراج الـ UUID من الرابط
            result_id = referer.strip('/').split('/')[-1]
            result = PhishingResult.objects.get(unique_id=result_id)

            # التقاط كل البيانات المرسلة
            captured_data = dict(request.POST)
            
            # تحديث سجل النتيجة
            result.submitted_data = True
            result.submitted_date = timezone.now()
            result.captured_data = captured_data
            result.save()

            # --- التكامل مع نظام التنبيهات! ---
            Alert.objects.create(
                timestamp=timezone.now(),
                description=f"[PHISHING] Credentials submitted by {result.target.email} in campaign '{result.campaign.name}'.",
                severity='CRITICAL',
                source_tool='Phishing Module',
                raw_log=captured_data
            )
            
            # إعادة توجيه الضحية إلى صفحة نهائية آمنة
            return redirect('https://www.google.com')

        except (PhishingResult.DoesNotExist, IndexError, ValueError):
            # في حالة وجود أي خطأ، أعد التوجيه بصمت
            return redirect('https://www.google.com')
    
    return redirect('https://www.google.com')

def phishing_campaign_detail_view(request, campaign_id):
    """
    يعرض تقريرًا مفصلاً لحملة تصيد، بما في ذلك إحصائيات الأداء وتحليل سلوك المستخدم.
    """
    campaign = get_object_or_404(PhishingCampaign, id=campaign_id)
    
    # جلب كل النتائج المرتبطة بهذه الحملة
    results = campaign.results.all().order_by('target__email')

    # --- 1. حساب الإحصائيات الأساسية ---
    total_targets = results.count()
    sent_count = results.filter(is_sent=True).count()
    opened_count = results.filter(is_opened=True).count()
    clicked_count = results.filter(is_clicked=True).count()
    submitted_count = results.filter(submitted_data=True).count()

    # حساب النسب المئوية (مع تجنب القسمة على صفر)
    open_rate = (opened_count / sent_count * 100) if sent_count > 0 else 0
    click_rate = (clicked_count / sent_count * 100) if sent_count > 0 else 0
    submission_rate = (submitted_count / sent_count * 100) if sent_count > 0 else 0
    
    # --- 2. حساب إحصائيات سلوك المستخدم ---
    average_time_to_click = None
    fastest_click_result = None

    # نقوم بهذا الحساب فقط إذا كان هناك نقرات لتحليلها
    if clicked_count > 0:
        # جلب كل النتائج التي تم النقر عليها ولها تاريخ إرسال ونقر صالح
        clicked_results_with_dates = results.filter(
            is_clicked=True, 
            sent_date__isnull=False, 
            clicked_date__isnull=False
        )
        
        # استخدام annotate لحساب الفارق الزمني لكل نقرة
        time_diffs_queryset = clicked_results_with_dates.annotate(
            time_to_click=ExpressionWrapper(F('clicked_date') - F('sent_date'), output_field=DurationField())
        )
        
        # حساب المتوسط باستخدام aggregate
        aggregation_result = time_diffs_queryset.aggregate(avg_time=Avg('time_to_click'))
        average_duration = aggregation_result.get('avg_time')
        
        if average_duration:
            # تحويل المتوسط إلى ثوانٍ لسهولة العرض
            average_time_to_click = int(average_duration.total_seconds())

        # العثور على أسرع نقرة من مجموعة النتائج التي تم حساب الفارق الزمني لها
        fastest_click_result = time_diffs_queryset.order_by('time_to_click').first()

    
    # --- إضافة جديدة: تجميع بيانات المواقع الجغرافية للخريطة ---
    locations_data = []
    # نقوم بتصفية النتائج التي تحتوي على بيانات جغرافية فقط
    geo_results = results.filter(captured_geolocation__isnull=False)

    for result in geo_results:
        geo_info = result.captured_geolocation
        # نتأكد من أن البيانات تحتوي على خطوط الطول والعرض
        if isinstance(geo_info, dict) and 'latitude' in geo_info and 'longitude' in geo_info:
            locations_data.append({
                'email': result.target.email,
                'lat': geo_info['latitude'],
                'lng': geo_info['longitude'],
            })
    # ----------------------------------------------------
    # --- إضافة جديدة: تصفية الأهداف الأكثر عرضة للخطر ---
    # هذه هي النتائج التي قام فيها المستخدم بكل الخطوات: فتح، نقر، وأدخل البيانات.
    at_risk_results = results.filter(submitted_data=True)
    
    # --- إضافة جديدة: حساب درجة مخاطر الحملة ---
    # المعادلة: نعطي وزنًا أكبر لإدخال البيانات (الأكثر خطورة)
    # ووزنًا أقل للنقر فقط.
    raw_score = 100 - (click_rate * 1.5) - (submission_rate * 3)
    if raw_score < 0:
        raw_score = 0

    # تحويل النتيجة الرقمية إلى درجة حرفية ولون
    if raw_score >= 90:
        risk_grade = 'A'
        risk_color = 'green' # أخضر
        risk_description = "Excellent Performance"
    elif raw_score >= 80:
        risk_grade = 'B'
        risk_color = 'teal' # تركواز
        risk_description = "Good Performance"
    elif raw_score >= 70:
        risk_grade = 'C'
        risk_color = 'yellow' # أصفر
        risk_description = "Average Performance - Needs Improvement"
    elif raw_score >= 60:
        risk_grade = 'D'
        risk_color = 'orange' # برتقالي
        risk_description = "Poor Performance - High Risk"
    else:
        risk_grade = 'F'
        risk_color = 'red' # أحمر
        risk_description = "Critical Risk - Immediate Action Required"
    # ----------------------------------------------------

    
    # --- 3. تجميع كل البيانات لتمريرها إلى القالب ---
    context = {
        'campaign': campaign,
        'results': results,
        
        # الإحصائيات الأساسية
        'total_targets': total_targets,
        'sent_count': sent_count,
        'opened_count': opened_count,
        'clicked_count': clicked_count,
        'submitted_count': submitted_count,
        'open_rate': open_rate,
        'click_rate': click_rate,
        'submission_rate': submission_rate,
        
        # إحصائيات السلوك الجديدة
        'average_time_to_click': average_time_to_click,
        'fastest_click_result': fastest_click_result,
         # تمرير بيانات الخريطة الجديدة إلى القالب
        'locations_data': locations_data,
         # تمرير القائمة الجديدة إلى القالب
        'at_risk_results': at_risk_results,
        
        # تمرير بيانات درجة المخاطرة الجديدة إلى القالب
        'risk_grade': risk_grade,
        'risk_color': risk_color,
        'risk_description': risk_description,
    }
    
    return render(request, 'core/phishing_campaign_detail.html', context)

@csrf_exempt # Disable CSRF protection as this request comes from a client-side script
def evidence_harvester_view(request, result_id):
    """
    API endpoint to receive collected evidence (User Agent, Geolocation, Image)
    from the landing page visited by the target.
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)

    try:
        # Find the result record using the unique UUID
        result = PhishingResult.objects.get(unique_id=result_id)
        
        # Read the data from the request body
        data = json.loads(request.body)

        # 1. Save User Agent and Geolocation data
        result.captured_user_agent = data.get('userAgent')
        result.captured_geolocation = data.get('geolocation')
        
        # 2. Get the victim's IP address
        #    (Using X-Forwarded-For for flexibility behind a proxy)
        result.captured_ip_address = request.META.get('HTTP_X_FORWARDED_FOR', request.META.get('REMOTE_ADDR'))

        # 3. Process and save the captured image (if it exists)
        image_data = data.get('image_data')
        
        # Ensure the data is a valid base64 image string
        if image_data and isinstance(image_data, str) and image_data.startswith('data:image/jpeg;base64,'):
            
            # Split the header from the actual image data
            format, imgstr = image_data.split(';base64,') 
            ext = format.split('/')[-1] # Extract the extension (jpeg)
            
            # Decode the binary data of the image
            decoded_file = base64.b64decode(imgstr)
            
            # Create a unique filename
            image_filename = f'{result.unique_id}.{ext}'
            
            # Define the save path within the media folder
            # (Requires MEDIA_ROOT and MEDIA_URL to be set in settings.py)
            save_dir = os.path.join(settings.MEDIA_ROOT, 'phishing_captures')
            os.makedirs(save_dir, exist_ok=True) # Create the directory if it doesn't exist
            
            file_path = os.path.join(save_dir, image_filename)

            # Write the image data to the file
            with open(file_path, 'wb+') as f:
                f.write(decoded_file)
            
            # Save the relative path of the image to the database
            result.captured_image_path = os.path.join('phishing_captures', image_filename)

        # Save all the updated fields to the database
        result.save()
        
        return JsonResponse({'status': 'success', 'message': 'Evidence received.'})

    except (PhishingResult.DoesNotExist, json.JSONDecodeError, Exception) as e:
        # Log the error for debugging but don't expose details to the client
        print(f"Error in evidence harvester: {e}")
        # Silently fail to avoid giving attackers information
        return JsonResponse({'status': 'error'}, status=400)