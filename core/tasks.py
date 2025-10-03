# core/tasks.py

import subprocess
import json
from celery import shared_task
from django.utils import timezone

import requests
from django.conf import settings
from .models import Scan, Vulnerability, Alert, ActionLog, Playbook
import os


# المسار الكامل لأداة Nikto
NIKTO_BIN = "/usr/local/bin/nikto"


@shared_task
def run_nikto_scan(scan_id):
    """
    Celery task لتشغيل أداة Nikto على هدف محدد وتخزين النتائج في قاعدة البيانات.
    """
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return f"Scan with id {scan_id} not found."

    report_path = f"/tmp/nikto_report_{scan.id}.json"
    command = [
        NIKTO_BIN,
        "-host", scan.target_url,
        "-output", report_path,
        "-Format", "json",
        "-nointeractive"
    ]

    # تحديث حالة الفحص
    scan.status = "RUNNING"
    scan.save()

    try:
        proc = subprocess.run(
            command,
            check=True,
            timeout=600,
            capture_output=True,
            text=True
        )

        # طباعة اللوق للمراجعة (stdout / stderr)
        print(f"[Nikto][Scan {scan.id}] STDOUT:\n{proc.stdout}")
        print(f"[Nikto][Scan {scan.id}] STDERR:\n{proc.stderr}")

        # تحقق من أن التقرير اتنشأ
        if not os.path.exists(report_path) or os.path.getsize(report_path) == 0:
            scan.status = "FAILED"
            scan.completed_at = timezone.now()
            scan.save()
            return f"Nikto did not produce a valid report at {report_path}."

        # قراءة تقرير JSON
        with open(report_path, "r") as f:
            report_data = json.load(f)

        # Nikto يعيد قائمة (list) من التقارير
        if not isinstance(report_data, list):
            report_data = [report_data]

        total_vulns = 0
        for host_report in report_data:
            vulns = host_report.get("vulnerabilities", [])
            for vuln in vulns:
                Vulnerability.objects.create(
                    scan=scan,
                    description=vuln.get("msg", vuln.get("description", "No description.")),
                    severity=vuln.get("id", "N/A"),
                    details=vuln
                )
                total_vulns += 1

        # تحديث حالة الفحص
        scan.status = "COMPLETED"
        scan.completed_at = timezone.now()
        scan.save()
        return f"Scan {scan.id} completed successfully with {total_vulns} vulnerabilities."

    except subprocess.CalledProcessError as e:
        print(f"[Nikto][Scan {scan.id}] Process failed. Return code={e.returncode}")
        print(f"STDOUT:\n{e.stdout}")
        print(f"STDERR:\n{e.stderr}")
        scan.status = "FAILED"
        scan.completed_at = timezone.now()
        scan.save()
        return f"Nikto process failed. Check worker logs."

    except subprocess.TimeoutExpired:
        scan.status = "FAILED"
        scan.completed_at = timezone.now()
        scan.save()
        return "Nikto scan timed out."

    except json.JSONDecodeError:
        scan.status = "FAILED"
        scan.completed_at = timezone.now()
        scan.save()
        return "Failed to decode Nikto JSON report."

    except Exception as e:
        print(f"[Nikto][Scan {scan.id}] Unexpected error: {str(e)}")
        scan.status = "FAILED"
        scan.completed_at = timezone.now()
        scan.save()
        return f"Unexpected error: {str(e)}"


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

    try:
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()

        data = response.json().get("data", {}).get("attributes", {})

        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        country = data.get("country", "N/A")
        owner = data.get("as_owner", "N/A")

        details = (
            f"VirusTotal analysis for {ip_address}:\n"
            f"- Malicious Votes: {malicious}\n"
            f"- Suspicious Votes: {suspicious}\n"
            f"- Country: {country}\n"
            f"- Owner: {owner}"
        )
        ActionLog.objects.create(alert=alert, playbook_run=playbook, details=details)
        return f"Successfully enriched IP {ip_address}."

    except requests.Timeout:
        details = f"VirusTotal API request timed out for IP {ip_address}."
    except requests.RequestException as e:
        details = f"VirusTotal API request failed for IP {ip_address}. Error: {str(e)}"

    ActionLog.objects.create(alert=alert, playbook_run=playbook, details=details)
    return details
