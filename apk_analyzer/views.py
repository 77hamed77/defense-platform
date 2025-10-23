# apk_analyzer/views.py
import hashlib
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db import models 
from .models import APKAnalysis
from core.tasks import analyze_apk_task # <-- سننشئ هذه المهمة
from .models import APKAnalysis, APKFinding # تأكد من وجود هذا
from .models import APKAnalysis, APKFinding # تأكد من وجود هذا
from core.tasks import analyze_apk_finding_with_ai # <-- سننشئ هذه المهمة
from core.tasks import run_dynamic_analysis_task  # استدعاء المهمة الجديدة

def apk_analysis_list_view(request):
    if request.method == 'POST' and request.FILES.get('apk_file'):
        apk_file = request.FILES['apk_file']
        
        # حساب الهاش للملف
        sha256_hash = hashlib.sha256(apk_file.read()).hexdigest()
        apk_file.seek(0) # إعادة المؤشر إلى بداية الملف

        # التحقق مما إذا كان هذا الملف قد تم تحليله من قبل
        existing_analysis = APKAnalysis.objects.filter(sha256_hash=sha256_hash).first()
        if existing_analysis:
            messages.warning(request, f"This APK file ('{existing_analysis.filename}') has already been analyzed.")
            return redirect('apk_analysis_list')

        # إنشاء سجل التحليل الجديد
        analysis = APKAnalysis.objects.create(
            apk_file=apk_file,
            filename=apk_file.name,
            sha256_hash=sha256_hash,
            status='PENDING'
        )
        
        # استدعاء مهمة Celery للقيام بالعمل الشاق
        analyze_apk_task.delay(str(analysis.id))
        
        messages.success(request, f"APK file '{apk_file.name}' uploaded successfully. Analysis has been scheduled.")
        return redirect('apk_analysis_list')

    analyses = APKAnalysis.objects.all().order_by('-created_at')
    context = {'analyses': analyses}
    return render(request, 'apk_analyzer/apk_analysis_list.html', context)


def apk_analysis_detail_view(request, analysis_id):
    analysis = get_object_or_404(APKAnalysis, id=analysis_id)
    
    # جلب كل الاكتشافات المرتبطة بهذا التحليل، مع ترتيبها حسب الخطورة
    findings = analysis.findings.all().order_by(
        models.Case(
            models.When(severity='CRITICAL', then=0),
            models.When(severity='HIGH', then=1),
            models.When(severity='MEDIUM', then=2),
            models.When(severity='LOW', then=3),
            default=4
        )
    )

    context = {
        'analysis': analysis,
        'findings': findings,
    }
    return render(request, 'apk_analyzer/apk_analysis_detail.html', context)


def analyze_finding_view(request, finding_id):
    if request.method == 'POST':
        finding = get_object_or_404(APKFinding, id=finding_id)
        
        # استدعاء المهمة في الخلفية
        analyze_apk_finding_with_ai.delay(finding.id)
        
        messages.info(request, "AI analysis has been scheduled. The report will appear below shortly (you may need to refresh).")
        
        # أعد التوجيه إلى نفس صفحة التقرير
        return redirect('apk_analysis_detail', analysis_id=finding.analysis.id)
    
    # إذا كان الطلب GET، فقط أعد التوجيه
    finding = get_object_or_404(APKFinding, id=finding_id)
    return redirect('apk_analysis_detail', analysis_id=finding.analysis.id)


# --- إضافة جديدة: عرض لبدء التحليل الديناميكي للتطبيقات ---
def run_dynamic_analysis_view(request, analysis_id):
    analysis = get_object_or_404(APKAnalysis, id=analysis_id)

    # استدعاء المهمة في الخلفية
    run_dynamic_analysis_task.delay(str(analysis.id))

    messages.info(request, "Dynamic analysis has been scheduled. Results will appear once completed.")
    return redirect('apk_analysis_detail', analysis_id=analysis.id)
