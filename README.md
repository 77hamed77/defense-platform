<div dir="ltr">
<div align="center">

```ascii
   ___         ___         ___         ___         ___
  /\  \       /\  \       /\  \       /\  \       /\__\
 /::\  \     /::\  \     /::\  \     /::\  \     /:/ _/_
/:/\:\  \   /:/\:\  \   /:/\:\  \   /:/\:\  \   /:/ /\  \
\:\~\:\  \ /::\~\:\  \ /::\~\:\  \ /::\~\:\  \ /:/ /::\  \
 \:\ \:\__\\/\:\ \:\__\\/\:\ \:\__\\/\:\ \:\__\\/__\/:/\:\__\
  \/_/:/  \ \:\~\:\/__/ \:\~\:\/__/ \:\~\:\/__/   /:/ /:/  /
     /:/  /   \:\ \:\  \  \:\ \:\  \  \:\ \:\  \  /:/ /:/  /
    /:/  /     \:\ \:\__\  \:\ \:\__\  \:\ \:\__\ /:/ /:/  /
   /:/  /       \:\/:/  /   \:\/:/  /   \:\/:/  / /:/ /:/  /
   \/__/         \::/  /     \::/  /     \::/  /  \/__\/__/
🛡️ Aegis Prime: Smart Cybersecurity Division Platform
Where Data Becomes Defense.
</div>
منصة قيادة استراتيجية مبنية باستخدام Django، مصممة لتحويل فوضى بيانات الأمن السيبراني إلى إجراءات حاسمة ومؤتمتة. Aegis Prime هو الجهاز العصبي المركزي للحصن الرقمي الحديث.
</div>
<!-- 🎬 CRITICAL: A GIF showcasing the main dashboard, a scan running, and the phishing report is ESSENTIAL to do this project justice. -->
<p align="center">
<!-- <img src="path/to/your/aegis-prime-demo.gif" width="90%"> -->
</p>
🛠️ ترسانة التقنيات (Tech Arsenal)
<div align="center">
Backend & SOAR	Task Queue	Database	Frontend
![alt text](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![alt text](https://img.shields.io/badge/Celery-37814A?style=for-the-badge&logo=celery&logoColor=white)
![alt text](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![alt text](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![alt text](https://img.shields.io/badge/Django-092E20?style=for-the-badge&logo=django&logoColor=white)
![alt text](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![alt text](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![alt text](https://img.shields.io/badge/DRF-A30000?style=for-the-badge&logo=django&logoColor=white)
![alt text](https://img.shields.io/badge/Chart.js-FF6384?style=for-the-badge&logo=chartdotjs&logoColor=white)
</div>
✨ القدرات الأساسية (Core Capabilities)
🎯 مركز قيادة مركزي: لوحة تحكم "Single Pane of Glass" تعرض تنبيهات حية، تحليلات للخطورة، ومؤشرات أداء رئيسية.
⚙️ محرك مسح ضوئي غير متزامن: ينسق مجموعة واسعة من أدوات الأمن مفتوحة المصدر (Nmap, Nuclei, SQLMap, Nikto, Subfinder, وغيرها) كمهام خلفية باستخدام Celery و Redis.
🤖 محرك أتمتة SOAR: ينفذ "Playbooks" معقدة بنقرة واحدة، من احتواء التهديدات الأولية إلى تحليل IP العميق عبر واجهات برمجة التطبيقات الخارجية (VirusTotal).
🎣 وحدة محاكاة تصيد متكاملة: إدارة حملات تصيد داخلية من الألف إلى الياء، بدءًا من استنساخ الصفحات إلى تتبع التفاعل (فتح، نقر، إرسال) وجمع الأدلة.
💥 إثبات المفهوم: من الاستطلاع إلى الاختراق الكامل
لإثبات القدرات الهجومية للمنصة، تم تنفيذ هجوم ناجح بالكامل:
الاستطلاع: تم إطلاق فحص Nmap من المنصة، والذي نجح في تحديد خدمة vsftpd 2.3.4 الضعيفة على جهاز افتراضي مستهدف.
الاستغلال المؤتمت: تم ربط الثغرة بوحدة Metasploit المقابلة وتشغيلها كـ "Playbook".
الاختراق: نجحت المهمة في الاتصال بخدمة Metasploit RPC، وإطلاق الاستغلال، والحصول على جلسة Shell بصلاحيات root على الجهاز المستهدف، مما يثبت قدرة المنصة على الانتقال بسلاسة من الاستطلاع إلى الاختراق الناجح.
<details>
<summary>📚 <strong>قائمة أدوات الفحص المدمجة (Integrated Scanner List)</strong></summary>
<div dir="ltr">
Network Mapping: Nmap
Web Vulnerability: Nikto, Nuclei
Directory & File Discovery: dirsearch
SQL Injection: SQLMap, Ghauri
Subdomain Enumeration: Subfinder, Amass
Secret Detection: Trufflehog
Specialized: XXEinjector, Subjack
</div>
</details>
<details>
<summary>🎣 <strong>تفاصيل وحدة محاكاة التصيد (Phishing Module Deep-Dive)</strong></summary>
استنساخ الصفحات: أداة مؤتمتة لاستنساخ HTML لأي صفحة تسجيل دخول وتعديلها لتوجيه البيانات إلى المنصة.
تتبع متعدد المراحل: يراقب النظام تفاعل المستخدم (Sent -> Opened -> Clicked -> Submitted).
جمع الأدلة: يقوم JavaScript بجمع الموقع الجغرافي، وكيل المستخدم، وحتى لقطة كاميرا الويب (بعد موافقة المتصفح) كدليل قاطع.
تقارير آلية: لوحة بيانات لكل حملة تتضمن ملخصاً تنفيذياً، مقاييس الأداء، خريطة جغرافية للمواقع المخترقة، ولوحة صدارة للمستخدمين الأكثر عرضة للخطر.
</details>
<details>
<summary>🔮 <strong>الرؤية المستقبلية وتكامل الذكاء الاصطناعي (Future Vision & AI Integration)</strong></summary>
توسيع ترسانة الأدوات: دمج أدوات DAST مثل OWASP ZAP و Burp Suite.
الجيل الثاني من وحدة التصيد:
إنشاء رسائل تصيد ذكية: استخدام Gemini 1.5 Flash API لتوليد رسائل بريد إلكتروني مقنعة ومخصصة تلقائيًا.
تحليل فوري لكلمات المرور: استخدام Gemini لتحليل كلمات المرور التي تم جمعها وتقييم قوتها ومقارنتها بقواعد بيانات التسريبات المعروفة.
كتابة تقارير آلية: استخدام الذكاء الاصطناعي لكتابة "الملخص التنفيذي" و "التوصيات" في تقارير الحملة.
</details>
<details>
<summary>⚙️ <strong>دليل الإعداد والتشغيل (Setup & Operation)</strong></summary>
<div dir="ltr">
المتطلبات: Python, Django, Redis, Metasploit Framework.
إعداد البيئة: قم باستنساخ المستودع، أنشئ بيئة افتراضية، وقم بتثبيت المكتبات من requirements.txt.
تشغيل الخدمات الأساسية:
code
Bash
# 1. Start Metasploit RPC Service
msfrpcd -P your_password -S

# 2. Start Redis Server
sudo service redis-server start

# 3. Run the Celery Worker
celery -A defense_platform worker -l info

# 4. Launch the Django Server
python manage.py runserver
الوصول للمنصة: اذهب إلى http://127.0.0.1:8000/.
</div>
</details>
👨‍💻 المؤلف (Author)
حامد محمد المرعي
<p>
<a href="https://github.com/77hamed77" target="_blank">
<img src="https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white" alt="GitHub">
</a>
<a href="https://www.linkedin.com/in/hamidmuhammad" target="_blank">
<img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn">
</a>
</p>
```
