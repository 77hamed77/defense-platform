# core/management/commands/create_superuser.py

import os
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

User = get_user_model()

class Command(BaseCommand):
    help = 'Creates a superuser from environment variables if one does not exist.'

    def handle(self, *args, **options):
        # تحقق مما إذا كان هناك أي مستخدمين بالفعل
        if User.objects.exists():
            self.stdout.write(self.style.SUCCESS('A user already exists. Skipping superuser creation.'))
            return

        # اقرأ بيانات الأدمن من متغيرات البيئة
        username = os.environ.get('ADMIN_USERNAME')
        email = os.environ.get('ADMIN_EMAIL')
        password = os.environ.get('ADMIN_PASSWORD')

        # تأكد من أن كل المتغيرات موجودة
        if not all([username, email, password]):
            self.stdout.write(self.style.ERROR('Missing ADMIN_USERNAME, ADMIN_EMAIL, or ADMIN_PASSWORD environment variables.'))
            return

        # قم بإنشاء الـ superuser
        User.objects.create_superuser(username=username, email=email, password=password)
        
        self.stdout.write(self.style.SUCCESS(f'Successfully created superuser: {username}'))