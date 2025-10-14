<div align="center">

```
   ___         ___         ___         ___         ___
  /\  \       /\  \       /\  \       /\  \       /\__\
 /::\  \     /::\  \     /::\  \     /::\  \     /:/ _/_
/:/\:\  \   /:/\:\  \   /:/\:\  \   /:/\:\  \   /:/ /\  \
\:\~\:\  \ /::\~\:\  \ /::\~\:\  \ /::\~\:\  \ /:/ /::\  \
 \:\ \:\__\\/\:\ \:\__\\/\:\ \:\__\\/\:\ \:\__\\/__\/:/\:\__\
  \/_/:/  / \:\~\:\/__/ \:\~\:\/__/ \:\~\:\/__/   /:/ /:/  /
     /:/  /   \:\ \:\  \  \:\ \:\  \  \:\ \:\  \  /:/ /:/  /
    /:/  /     \:\ \:\__\  \:\ \:\__\  \:\ \:\__\ /:/ /:/  /
   /:/  /       \:\/:/  /   \:\/:/  /   \:\/:/  / /:/ /:/  /
   \/__/         \::/  /     \::/  /     \::/  /  \/__\/__/
```

# Aegis Prime: Smart Cybersecurity Division Platform

**_Where Data Becomes Defense._**

</div>

> Aegis Prime is not just a security tool; it's the centralized nervous system for the modern digital fortress. It is a comprehensive, Django-based strategic command center where the chaos of cybersecurity data is forged into decisive, automated action. Built for elite security teams, this platform transforms reactive measures into a proactive, intelligence-driven defense posture, covering the full lifecycle from reconnaissance and vulnerability scanning to exploitation and phishing simulation.

---

## 🚀 The Arsenal: A Detailed Breakdown of Core Features

Aegis Prime is built upon a philosophy of **Intelligence, Speed, and Orchestration**. Each feature is a modular weapon in the arsenal of the cyber defender, designed to work in concert.

### 1. **Command Center (Centralized Dashboard)**
The operational heart of Aegis Prime, providing a real-time, "Single Pane of Glass" overview of the security landscape.
- **Live Alert Feed:** Displays the latest security alerts ingested from all integrated sources.
- **Heads-Up Display:** At-a-glance metrics for total alerts, managed assets, and tracked Indicators of Compromise (IOCs).
- **Severity Analytics:** An interactive doughnut chart powered by **Chart.js** visualizes the distribution of alerts by severity (Low, Medium, High, Critical), allowing for immediate trend analysis.

### 2. **The Oracle (Intelligent Alerting & Correlation Engine)**
The Oracle ingests raw data and outputs wisdom, automating the initial stages of triage.
- **Universal Ingestion:** A secure, API-key-protected endpoint built with **Django REST Framework** consumes alerts in JSON format from any external tool (IDS/IPS, SIEMs, custom scripts).
- **Automated Correlation:** The platform maintains a dynamic database of known IOCs. The ingestion engine automatically cross-references the source IP of every incoming alert against this database.
- **Automatic Escalation:** A low-level alert (`LOW`, `MEDIUM`) that matches a known hostile IOC is **instantly and automatically escalated to `CRITICAL`**, its description is prepended with `[IOC MATCH FOUND]`, ensuring that known threats receive immediate attention without human intervention.

### 3. **Scanner Orchestrator (Modular & Asynchronous Scanning Engine)**
A powerful and extensible engine that orchestrates a diverse arsenal of best-in-class open-source security tools.
- **Modular Framework:** The engine is built around a `Tool` model in the database, allowing new command-line tools to be added and configured directly from the admin panel without changing a single line of code.
- **Fully Asynchronous Operations:** All scans are executed as background jobs using **Celery** and **Redis**. This ensures the UI remains fast and responsive, providing instant user feedback while handling long-running tasks (up to an hour or more).
- **Interactive Control:** Active scans display a real-time duration counter and a "Stop" button, allowing analysts to terminate long-running jobs.
- **Dynamic UI:** The frontend uses JavaScript to poll a status API for running scans, automatically refreshing the page upon completion to display results.
- **Detailed Reporting:** Each scan generates a detailed report page listing all findings, which can be inspected individually.

#### **Integrated Scanning Arsenal:**
- **Network & Service Mapping:**
    - **`Nmap`:** For active port scanning, service identification, and version detection.
- **Web Vulnerability & Reconnaissance:**
    - **`Nikto`:** For rapid, preliminary web server vulnerability scanning.
    - **`dirsearch`:** For discovering hidden or unlinked files, directories, and API endpoints.
    - **`SQLMap` & `Ghauri`:** A dual-threat capability for detecting and confirming SQL injection vulnerabilities.
- **Subdomain Enumeration:**
    - **`Subfinder` & `Amass`:** Two powerful tools for comprehensive subdomain discovery using passive sources.
- **Advanced Vulnerability Detection:**
    - **`Nuclei`:** A fast, modern, template-based scanner for detecting a vast range of vulnerabilities, from misconfigurations to known CVEs.
- **Secret Detection:**
    - **`Trufflehog`:** Scans Git repositories for leaked secrets, API keys, and credentials.
- **Specialized Scanners:**
    - **`XXEinjector` & `Subjack`:** For detecting highly specific, high-impact vulnerabilities like XXE injection and Subdomain Takeover.

### 4. **The Automaton (SOAR & Playbook Engine)**
The heart of the platform's automation, enabling the execution of complex, multi-step response and enrichment sequences with a single click.
- **▶️ Playbook: "Initial Threat Containment"**: A first-response action that automatically creates a new IOC from an alert's source IP, adding it to the threat intelligence database, and marking the alert as `In Progress`.
- **▶️ Playbook: "Deep IP Analysis"**: An intelligence-gathering operation. This Celery-powered playbook queries the **VirusTotal API** for an attacker's IP, enriching the alert with critical reputation data (malicious votes, geographical origin, ISP owner), and appends this context directly to the alert's permanent action log.
- **▶️ Playbook: "Recon & Attack Chain"**: A true orchestration sequence. This playbook first runs **`Subfinder`** to discover all subdomains of a target, then automatically feeds the entire list into **`Nuclei`** for a comprehensive vulnerability scan.

### 5. **Successful Exploitation & Proof of Concept**
To validate the platform's full offensive capabilities, a successful end-to-end attack was orchestrated and executed:
1.  A vulnerable virtual machine (**Metasploitable2**) was set up as a sandboxed target.
2.  An **`Nmap`** scan was initiated from the platform, which successfully identified the `vsftpd 2.3.4` service.
3.  The corresponding Metasploit module (`exploit/unix/ftp/vsftpd_234_backdoor`) was linked to the vulnerability in the database.
4.  The "Test Exploit" button was triggered from the scan report page, scheduling a Celery task.
5.  The task successfully connected to the **Metasploit RPC service (`msfrpcd`)**, configured the exploit, and launched it against the target.
6.  **Verification confirmed that a command shell session was opened, achieving `root` access on the target machine.** This demonstrates the platform's ability to seamlessly pivot from reconnaissance to successful exploitation.

### 6. **Phishing Simulation & Human Risk Management Module**
A complete, end-to-end module for creating, launching, and analyzing internal phishing campaigns to measure and improve human security awareness.
- **Page Cloner:** An automated tool to clone the HTML of any public login page, intelligently modify its forms to point to our harvester, and save it as a landing page template.
- **Campaign Management:** A full-featured interface to create and manage campaigns, combining email templates, landing pages, and target lists.
- **Multi-Stage Tracking:** The system tracks every user interaction:
    1.  **Email Sent:** Confirms delivery.
    2.  **Email Opened:** A 1x1 tracking pixel logs when the email is viewed.
    3.  **Link Clicked:** A unique tracking URL logs the click before redirecting the user.
    4.  **Data Submitted:** A credential harvester endpoint captures submitted data.
- **Evidence Gathering:** An injected JavaScript payload on the landing page captures **geolocation**, **user agent**, and even a **webcam snapshot** (with user consent prompted by the browser), providing undeniable proof of compromise.
- **Automated Reporting:** A detailed report page is generated for each campaign, featuring:
    - **Executive Risk Summary:** A high-level overview for management.
    - **Performance Metrics:** Funnel statistics (Sent -> Opened -> Clicked -> Submitted).
    - **Behavior Analysis:** Calculates "Time-to-Click" and identifies the fastest responders.
    - **Geographic Map:** An interactive **Leaflet.js** map visualizes the locations of compromised users.
    - **At-Risk Leaderboard:** Highlights the specific users who submitted credentials.
    - **Actionable Recommendations:** Provides clear, prioritized steps for remediation and training.

---

## 🔮 Future Vision & Roadmap

Aegis Prime is a living project with an ambitious roadmap for future development.

### 1. **Expansion of the Tool Arsenal**
The modular framework is built for growth. The next phase will focus on integrating more advanced and diverse tools:
- **DAST Integration:** Build connectors for the APIs of dynamic scanners like **OWASP ZAP** and **Burp Suite Professional**.
- **Visual Reconnaissance:** Integrate **Eyewitness** into playbooks to take screenshots of discovered web services.
- **Cloud Security:** Add tools for scanning cloud configurations (e.g., for AWS S3 buckets, IAM policies).

### 2. **AI-Powered Phishing Module 2.0**
The current phishing module is powerful, but the next generation will be intelligent.
- **AI-Generated Lures:** Utilize the **Gemini 1.5 Flash API** to automatically generate convincing, context-aware phishing email bodies and subjects, tailored to specific targets or industries.
- **AI-Powered Credential Analysis:** Integrate Gemini to analyze captured credentials in real-time. The AI will assess password complexity, check against known breach databases (via APIs like Have I Been Pwned), and provide an instant risk score.
- **Automated Report Generation:** Use AI to write the "Executive Summary" and "Recommendations" sections of the phishing report automatically based on the campaign's results.

This strategic evolution will solidify Aegis Prime's position as an indispensable tool for proactive, intelligence-driven cybersecurity operations.

---

## 🛠️ Tech Stack & Architecture
*(This section can remain as it was in the previous README, as it is still accurate)*

## ⚙️ System Setup & Installation
*(This section can remain as it was, but you should add the new dependencies like `pymetasploit3`, `google-generativeai`, etc., to the `requirements.txt` file mentioned)*

## ⚡ Usage & Operation
*(This section should be updated to include the `msfrpcd` service)*

1.  **Start the Metasploit RPC Service:** `msfrpcd -P your_password -S`
2.  **Start the Redis Server:** `sudo service redis-server start`
3.  **Run the Celery Worker:** `celery -A defense_platform worker -l info`
4.  **Launch the Django Server:** `python manage.py runserver`

> Once all services are running, navigate to `http://127.0.0.1:8000` to access the **Command Center**.