import os
from pathlib import Path
from dotenv import load_dotenv
import dj_database_url

# --- الخطوة 1: تحميل متغيرات البيئة ---
# هذا سيقوم بقراءة ملف .env الخاص بك في بيئة التطوير المحلية
load_dotenv()

# --- الإعدادات الأساسية ---
BASE_DIR = Path(__file__).resolve().parent.parent

# اقرأ المفتاح السري من متغيرات البيئة. هام جدًا للإنتاج!
SECRET_KEY = os.environ.get('SECRET_KEY', 'django-insecure-fallback-key-for-local-dev-only')

# اقرأ حالة DEBUG من متغيرات البيئة. يجب أن تكون 'False' في الإنتاج.
DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

# اقرأ قائمة المضيفين المسموح بهم.
# في ملف .env، يجب أن تكون هكذا: ALLOWED_HOSTS=127.0.0.1,localhost,your-render-app.onrender.com
allowed_hosts_str = os.environ.get('ALLOWED_HOSTS', '127.0.0.1,localhost')
ALLOWED_HOSTS = [host.strip() for host in allowed_hosts_str.split(',') if host.strip()]

# أضف رابط Render تلقائيًا إذا كان موجودًا
RENDER_EXTERNAL_HOSTNAME = os.environ.get('RENDER_EXTERNAL_HOSTNAME')
if RENDER_EXTERNAL_HOSTNAME:
    ALLOWED_HOSTS.append(RENDER_EXTERNAL_HOSTNAME)

# --- التطبيقات والبرمجيات الوسيطة ---
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'whitenoise.runserver_nostatic',  # <-- لـ Whitenoise
    'django.contrib.staticfiles',
    'rest_framework_api_key',
    'rest_framework',
    'core',
    'django_filters',
    'vulnerable_app',
    'network_mapper',
    'django_extensions',
    'apk_analyzer',
    'cloud_scanner',
    'storages',  # <-- لإدارة التخزين على S3
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # <-- لـ Whitenoise
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'defense_platform.urls'
WSGI_APPLICATION = 'defense_platform.wsgi.application'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# --- قاعدة البيانات (مرنة للإنتاج والتطوير) ---
# ستقرأ من DATABASE_URL في ملف .env، وإذا لم تجده، ستستخدم SQLite المحلي.
DATABASES = {
    'default': dj_database_url.config(
        default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}",
        conn_max_age=600
    )
}

# --- التحقق من صحة كلمة المرور ---
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# --- التدويل (Internationalization) ---
LANGUAGE_CODE = 'ar'
TIME_ZONE = 'Asia/Damascus'
USE_I18N = True
USE_L10N = True
USE_TZ = True

# --- الملفات الثابتة (Static) والوسائط (Media) ---

# الإعدادات الأساسية للملفات الثابتة
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
# إعدادات Whitenoise لتخزين الملفات الثابتة بكفاءة في الإنتاج
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# إعدادات تخزين ملفات الوسائط على Supabase S3
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_STORAGE_BUCKET_NAME = os.environ.get('AWS_STORAGE_BUCKET_NAME')
AWS_S3_REGION_NAME = os.environ.get('AWS_S3_REGION_NAME')
AWS_S3_ENDPOINT_URL = os.environ.get('AWS_S3_ENDPOINT_URL')
# إعدادات إضافية لتحسين الأداء
AWS_S3_OBJECT_PARAMETERS = {'CacheControl': 'max-age=86400'}
AWS_LOCATION = 'media' # سيتم إنشاء مجلد media داخل الـ bucket

# روابط URL للملفات
MEDIA_URL = f"{AWS_S3_ENDPOINT_URL}/{AWS_STORAGE_BUCKET_NAME}/{AWS_LOCATION}/"


# --- إعدادات Celery ---
# ستقرأ من REDIS_URL في بيئة الإنتاج، وإذا لم تجده، ستستخدم Redis المحلي.
REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'

# --- مفاتيح API الخارجية ---
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')

# --- إعدادات البريد الإلكتروني ---
EMAIL_BACKEND = os.environ.get('EMAIL_BACKEND', 'django.core.mail.backends.console.EmailBackend')
EMAIL_HOST = os.environ.get('EMAIL_HOST')
EMAIL_PORT = int(os.environ.get('EMAIL_PORT', 587))
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'True').lower() == 'true'
EMAIL_HOST_USER = os.environ.get('EMAIL_HOST_USER')
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL')
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')

# --- إعدادات أخرى ---
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'