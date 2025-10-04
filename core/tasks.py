# core/tasks.py

import subprocess
import json
import os
from celery import shared_task
from django.utils import timezone
import requests
from django.conf import settings
from .models import Scan, Vulnerability, Alert, ActionLog, Playbook, Tool

# --- المهمة الرئيسية لتنسيق عمليات الفحص ---

@shared_task
def execute_scan_task(scan_id):
    """
    مهمة Celery عامة تقوم بتشغيل أي أداة فحص معرفة في قاعدة البيانات.
    """
    try:
        # جلب كائن الفحص والأداة المرتبطة به
        scan = Scan.objects.get(id=scan_id)
        tool = scan.tool
    except (Scan.DoesNotExist, Tool.DoesNotExist):
        print(f"ERROR: Scan or Tool not found for scan_id {scan_id}.")
        return f"Scan or Tool not found for scan_id {scan_id}."

    # تحديث الحالة إلى "قيد التشغيل"
    scan.status = 'RUNNING'
    scan.save()
    
    # تحديد مسار فريد لملف التقرير المؤقت
    output_file = f"/tmp/scan_report_{scan_id}.txt"
    
    # بناء الأمر ديناميكيًا من القالب الموجود في قاعدة البيانات
    command_str = tool.command_template.format(target=scan.target_url, output=output_file)
    command_args = command_str.split()

    result_message = ""
    print(f"Executing command for scan {scan.id}: {' '.join(command_args)}")

    try:
        # تنفيذ الأمر
        result = subprocess.run(
            command_args, 
            check=True,         # سيسبب خطأ إذا كان exit code غير 0
            timeout=3600,       # مهلة 60 دقيقة
            capture_output=True,
            text=True
        )
        # طباعة المخرجات في سجل Celery للتشخيص
        print(f"[{tool.name} Scan {scan.id}] STDOUT:\n{result.stdout}")
        print(f"[{tool.name} Scan {scan.id}] STDERR:\n{result.stderr}")

        # --- منطق تحليل المخرجات بناءً على اسم الأداة ---
        if tool.name == 'Nikto':
            parse_nikto_json(scan, output_file)
        elif tool.name == 'Nmap':
            parse_nmap_text(scan, output_file)
        # يمكنك إضافة دوال تحليل لأدوات أخرى هنا
        
        scan.status = 'COMPLETED'
        result_message = f"{tool.name} scan for {scan.target_url} completed successfully."

    except subprocess.CalledProcessError as e:
        scan.status = 'FAILED'
        result_message = f"{tool.name} process failed. Check worker logs for details."
        # طباعة الخطأ الفعلي من الأداة
        print(f"ERROR for scan {scan.id}: {tool.name} failed with exit code {e.returncode}")
        print(f"STDERR from tool:\n{e.stderr}")
    except subprocess.TimeoutExpired:
        scan.status = 'FAILED'
        result_message = f"Scan timed out after 30 minutes."
    except Exception as e:
        scan.status = 'FAILED'
        result_message = f"An unexpected error occurred: {str(e)}"
        print(f"UNEXPECTED ERROR for scan {scan.id}: {str(e)}")
    
    finally:
        # تحديث الكائن في قاعدة البيانات وحذف الملف المؤقت
        scan.completed_at = timezone.now()
        scan.save()
        if os.path.exists(output_file):
            os.remove(output_file)

    print(result_message)
    return result_message

# --- دوال مساعدة لتحليل مخرجات الأدوات ---

def parse_nikto_json(scan, file_path):
    """
    تحلل تقرير Nikto بصيغة JSON، مع معالجة التنسيقات المختلفة.
    """
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        print(f"Nikto report file not found or is empty: {file_path}")
        return

    with open(file_path, 'r') as f:
        try:
            report_data = json.load(f)
        except json.JSONDecodeError:
            print(f"Error decoding JSON from Nikto report: {file_path}")
            # يمكنك هنا إضافة منطق لقراءة الملف كنص عادي وتسجيله
            return

    # --- منطق ذكي للتعامل مع التنسيقات المختلفة ---
    hosts = []
    if isinstance(report_data, dict):
        # التنسيق القياسي والناجح
        hosts = report_data.get('hosts', [])
    elif isinstance(report_data, list):
        # حالة خاصة قد تحدث عند وجود أخطاء
        # نفترض أن كل عنصر في القائمة هو تقرير مضمن
        hosts = report_data

    if not hosts:
        print(f"No 'hosts' found in Nikto report for scan {scan.id}")
        return
    # ----------------------------------------------
        
    for host_report in hosts:
        # التأكد من أن host_report هو قاموس قبل استخدام .get()
        if not isinstance(host_report, dict):
            continue

        for vuln in host_report.get('vulnerabilities', []):
            Vulnerability.objects.create(
                scan=scan, 
                description=vuln.get('description', 'No description provided.'), 
                severity=vuln.get('id', 'N/A'), 
                details=vuln
            )

def parse_nmap_text(scan, file_path):
    """
    تحلل تقرير Nmap النصي (مخرجات -oN) وتنشئ سجلات للبورتات المفتوحة.
    """
    if not os.path.exists(file_path):
        print(f"Nmap report file not found: {file_path}")
        return
        
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            # البحث عن الأسطر التي تحتوي على بورت مفتوح
            if '/tcp' in line and 'open' in line:
                parts = [p for p in line.split() if p] # تقسيم السطر وإزالة المسافات الزائدة
                if len(parts) >= 3:
                    port = parts[0]
                    service = " ".join(parts[2:])
                    Vulnerability.objects.create(
                        scan=scan, 
                        description=f"Open Port: {port} - Service: {service}",
                        severity="Informational", 
                        details={'port': port, 'service': service, 'raw_line': line}
                    )

# --- مهمة إثراء البيانات من VirusTotal ---

@shared_task
def enrich_ip_with_virustotal(alert_id, playbook_id):
    """
    Celery task لإغناء عنوان IP باستخدام VirusTotal API.
    """
    try:
        alert = Alert.objects.get(id=alert_id)
        playbook = Playbook.objects.get(id=playbook_id)
    except (Alert.DoesNotExist, Playbook.DoesNotExist):
        return f"Alert or Playbook not found."

    if not alert.source_ip:
        details = "Playbook failed: Alert has no source IP address."
        ActionLog.objects.create(alert=alert, playbook_run=playbook, details=details)
        return details

    ip_address = alert.source_ip
    api_key = settings.VIRUSTOTAL_API_KEY
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    details = ""

    try:
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        data = response.json().get('data', {}).get('attributes', {})
        
        stats = data.get('last_analysis_stats', {})
        details = (
            f"VirusTotal analysis for {ip_address}:\n"
            f"- Malicious: {stats.get('malicious', 0)}, Suspicious: {stats.get('suspicious', 0)}\n"
            f"- Country: {data.get('country', 'N/A')}\n"
            f"- Owner: {data.get('as_owner', 'N/A')}"
        )
        ActionLog.objects.create(alert=alert, playbook_run=playbook, details=details)
        return f"Successfully enriched IP {ip_address}."

    except requests.RequestException as e:
        details = f"VirusTotal API request failed for IP {ip_address}. Error: {str(e)}"
        ActionLog.objects.create(alert=alert, playbook_run=playbook, details=details)
        return details