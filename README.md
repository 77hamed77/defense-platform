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

# Aegis Prime

**_Where data becomes defense._**

</div>

> Aegis Prime is not just a security tool; it's the centralized nervous system for the modern digital fortress. It is a strategic command center where the chaos of cybersecurity data is forged into decisive, automated action. Built for elite security teams, this platform transforms reactive measures into a proactive, intelligent defense posture.

---

## 🚀 The Arsenal: Core Features

Aegis Prime is built upon a philosophy of intelligence, speed, and automation. Each feature is a weapon in the arsenal of the cyber defender.

###  CommandCenter (Dashboard)
The operational heart of Aegis Prime. This is the real-time, heads-up display for cyber warfare, providing immediate situational awareness.
- **Dynamic Battle Map:** Visualizes global threat origins.
- **Heads-Up Display:** Key metrics on alerts, assets, and active threats.
- **Severity Analytics:** Interactive visualizations powered by **Chart.js** reveal threat patterns at a glance.

### 🔮 The Oracle (Intelligent Alerting & Correlation)
The Oracle ingests raw data and outputs wisdom. It sees the patterns before a human can.
- **Universal Ingestion:** A secure **Django REST Framework API** consumes alerts from any source (IDS, SIEMs, custom scripts).
- **Correlation Engine:** Incoming alerts are instantly cross-referenced against a live threat intelligence database of **Indicators of Compromise (IOCs)**.
- **Automatic Escalation:** A low-level alert from an IP matching a known hostile entity is **instantly escalated to `CRITICAL`** and tagged `[IOC MATCH FOUND]`, bypassing human delay.

### 🔭 The Hunter (Asynchronous Vulnerability Scanner)
Unleash the power of **Nikto** without ever leaving the command center. The Hunter operates with unparalleled efficiency.
- **On-Demand Scans:** Initiate scans against any target with a single click.
- **Fully Asynchronous:** Engineered with **Celery & Redis**, scans run in the background. The UI remains fluid and responsive, providing an instant "task scheduled" confirmation.
- **Real-Time Feedback:** The interface automatically polls for status updates and live-reloads upon completion to present a detailed, actionable report.

### 🤖 The Automaton (SOAR Playbook Engine)
This is where strategy meets execution. The Automaton is a library of one-click "Playbooks" that execute complex response sequences, eliminating human error and minimizing response time.
- **▶️ Playbook: "Containment Protocol"**: A first-response action that instantly blocklists an attacker's IP by adding it to the IOC database, neutralizing the immediate threat.
- **▶️ Playbook: "Deep Scan"**: An intelligence-gathering operation. This Celery-powered playbook queries the **VirusTotal API** for an attacker's IP, enriching the alert with critical reputation data, geographical origin, and ownership details.

### 📂 The Archives (Proactive Threat Hunting)
The Archives turn historical data into a hunting ground. This is the analyst's playground for proactively uncovering hidden threats.
- **High-Fidelity Search:** A powerful interface built with `django-filter` allows for deep-diving into all historical alerts.
- **Multi-Vector Filtering:** Search by IP, severity, status, date range, or free-text description to connect the dots and identify campaign-level activity.

### 👻 The Ghost (Deception Technology)
The Ghost lays silent traps for the unwary. It's the ultimate early-warning system.
- **Honeypot Endpoint:** A strategically placed, decoy API endpoint (`/api/v1/user/login`) that appears to be a forgotten vulnerability.
- **Silent Alarm:** Any interaction with the honeypot is a tripwire. The system **instantly and silently** logs a `CRITICAL` alert, captures the attacker's digital fingerprint (IP, user-agent), and adds them to the IOC database before they even know they've been detected.

---

## 🛠️ Tech Stack & Architecture

Aegis Prime is forged from a robust and scalable technology stack, chosen for performance and reliability.

| Category              | Technology                                       | Purpose                                            |
| --------------------- | ------------------------------------------------ | -------------------------------------------------- |
| **Backend Framework** | ![Python](https://img.shields.io/badge/-Python-3776AB?logo=python&logoColor=white) ![Django](https://img.shields.io/badge/-Django-092E20?logo=django&logoColor=white) | Core application logic, security, and scalability. |
| **API Layer**         | ![Django REST Framework](https://img.shields.io/badge/-DRF-A30000?logo=django&logoColor=white) | Secure, high-performance alert ingestion.        |
| **Frontend**          | ![HTML5](https://img.shields.io/badge/-HTML5-E34F26?logo=html5&logoColor=white) ![Tailwind CSS](https://img.shields.io/badge/-Tailwind_CSS-38B2AC?logo=tailwind-css&logoColor=white) ![JavaScript](https://img.shields.io/badge/-JavaScript-F7DF1E?logo=javascript&logoColor=black) | A clean, responsive, and modern user interface.    |
| **Asynchronous Tasks**| ![Celery](https://img.shields.io/badge/-Celery-37814A?logo=celery&logoColor=white) ![Redis](https://img.shields.io/badge/-Redis-DC382D?logo=redis&logoColor=white) | Non-blocking background jobs for scanning & APIs.  |
| **Database**          | ![PostgreSQL](https://img.shields.io/badge/-PostgreSQL-336791?logo=postgresql&logoColor=white) | Robust, production-ready data persistence.       |
| **Integrated Tools**  | `Nikto`, `VirusTotal API`                        | External power for vulnerability and threat analysis. |

---

## ⚙️ System Setup & Installation

To deploy Aegis Prime on your own infrastructure, follow these steps:

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/your-username/aegis-prime.git
    cd aegis-prime
    ```

2.  **Set Up Virtual Environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment Variables:**
    - Create a `.env` file in the project root.
    - Add your secret keys:
      ```env
      SECRET_KEY='your-django-secret-key'
      VIRUSTOTAL_API_KEY='your-virustotal-api-key'
      ```
    - Update `settings.py` to read these variables.

5.  **Run Database Migrations:**
    ```bash
    python manage.py migrate
    ```

6.  **Create a Superuser:**
    ```bash
    python manage.py createsuperuser
    ```

---

## ⚡ Usage & Operation

Aegis Prime requires three core processes to run concurrently.

1.  **Start the Redis Server:**
    ```bash
    sudo service redis-server start
    ```

2.  **Run the Celery Worker:**
    (In a new terminal window)
    ```bash
    source venv/bin/activate
    celery -A aegis_prime worker -l info
    ```

3.  **Launch the Django Server:**
    (In another terminal window)
    ```bash
    source venv/bin/activate
    python manage.py runserver
    ```

> Once all services are running, navigate to `http://127.0.0.1:8000` to access the **Command Center**.

<div align="center">

**Aegis Prime // Forging the future of cyber defense.**

</div>