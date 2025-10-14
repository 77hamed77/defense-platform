# vulnerable_app/views.py
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from lxml import etree

@csrf_exempt
def xxe_vulnerable_endpoint(request):
    if request.method == 'POST':
        try:
            # هذا هو السطر الضعيف: يقوم بتحليل XML بدون أي حماية
            xml_data = request.body
            root = etree.fromstring(xml_data)
            
            # يعكس اسم العنصر الأول للتأكيد
            response_text = f"Received XML with root element: {root.tag}"
            return HttpResponse(response_text, content_type="text/plain")
        except Exception as e:
            return HttpResponse(f"Error processing XML: {e}", status=400)
    
    return HttpResponse("This endpoint accepts POST requests with XML data.", status=200)