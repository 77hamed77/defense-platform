#!/usr/bin/env bash
# exit on error
set -o errexit

echo "🚀 بدء عملية البناء..."

# 1. تحديث وتثبيت حزم Python
pip install --upgrade pip
pip install -r requirements.txt

# 2. جمع الملفات الثابتة (لـ Whitenoise)
echo "📦 جمع الملفات الثابتة..."
python manage.py collectstatic --no-input

# 3. تطبيق الهجرات على قاعدة البيانات
echo "Applying database migrations..."
python manage.py migrate

# 4. إنشاء المستخدم الخارق (Superuser) إذا لم يكن موجودًا
echo "Creating superuser (if none exists)..."
python manage.py create_superuser

echo "✅ انتهى build.sh بنجاح"