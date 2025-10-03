# core/management/commands/fetch_iocs.py

from django.core.management.base import BaseCommand
from core.models import IndicatorOfCompromise

# قائمة IOCs وهمية تحاكي ما قد نحصل عليه من API خارجي
MOCK_THREAT_FEED = [
    {'type': 'IP', 'value': '203.0.113.55', 'source': 'ThreatFeed #1'},
    {'type': 'DOMAIN', 'value': 'malicious-domain.example.com', 'source': 'ThreatFeed #1'},
    {'type': 'HASH', 'value': 'e8a3b64e621c828d998018449b1a7337', 'source': 'ThreatFeed #2'},
    {'type': 'IP', 'value': '198.51.100.10', 'source': 'ThreatFeed #1'}, # IOC مكرر لاختبار المنطق
]

class Command(BaseCommand):
    help = 'Fetches new Indicators of Compromise from a simulated external threat feed.'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Starting IOC import process...'))
        
        created_count = 0
        skipped_count = 0

        for item in MOCK_THREAT_FEED:
            # get_or_create هي الطريقة المثلى لمنع التكرار
            ioc, created = IndicatorOfCompromise.objects.get_or_create(
                value=item['value'],
                defaults={
                    'ioc_type': item['type'],
                    'source': item['source']
                }
            )

            if created:
                self.stdout.write(f"  [+] Created new IOC: {ioc.value} (Type: {ioc.ioc_type})")
                created_count += 1
            else:
                self.stdout.write(f"  [*] Skipped existing IOC: {ioc.value}")
                skipped_count += 1
        
        self.stdout.write(self.style.SUCCESS(f'\nImport process finished. Created: {created_count}, Skipped: {skipped_count}.'))