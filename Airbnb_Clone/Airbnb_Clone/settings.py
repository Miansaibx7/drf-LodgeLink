from pathlib import Path
from datetime import timedelta
from decouple import config, Csv

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET_KEY')


# SECURITY WARNING: don't run with debug turned on in production!

# FIX (security bug): DEBUG was hardcoded to True. Shipping DEBUG=True to
# production leaks full stack traces, local file paths, settings values, and
# SQL queries to anyone who can trigger a 500 — a critical info-disclosure
# risk. It must be driven by the environment and default to False.
DEBUG = config('DEBUG', default=False, cast=bool)


# Allows hosts - update this with your domain when moving to production.

# FIX: ALLOWED_HOSTS was an empty list. With DEBUG=False (as it now
# correctly is by default) Django will refuse ALL requests until this is
# set. Read from env so each environment (local/staging/prod) configures its
# own hosts.
ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1', cast=Csv())

# Allows every frontend to call your API.
# In production, you may want to change this to False and use CORS_ALLOWED_ORIGINS

# FIX (security bug): CORS_ALLOW_ALL_ORIGINS = True lets ANY website's
# JavaScript make authenticated (well, credentialed) requests to your API.
# Combined with JWT-in-body this is somewhat mitigated (no cookies), but it
# still allows any origin to hit your login/OTP endpoints, which is exactly
# the kind of thing your OTPRateThrottle/LoginRateThrottle are trying to
# guard against, and it makes CSRF-adjacent abuse trivial. Lock this down to
# an explicit allowlist driven by env config; only allow-all in local DEBUG.
CORS_ALLOW_ALL_ORIGINS = DEBUG
CORS_ALLOWED_ORIGINS = config('CORS_ALLOWED_ORIGINS', default='', cast=Csv())

# Allows Custom User Models Instead of Django's default User model.
AUTH_USER_MODEL = "accounts.User"

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party apps
    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',

    # Local apps
    'accounts',
]


# Argon2 first (current best-practice default against GPU cracking), PBKDF2
# kept as a fallback so existing PBKDF2 hashes (if any) still verify — Django
# rehashes to the first hasher transparently on next successful login.
# `pip install argon2-cffi` (or `uv add argon2-cffi`) is required for this.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
]


# Django REST Framework Configuration
REST_FRAMEWORK = {
    # 1. Authentication & Permissions
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
    
    # 2. Custom Exception Handler (Added from previous step)
    # IMPORTANT: Change 'accounts' to the app name where you saved exceptions.py
    'EXCEPTION_HANDLER': 'accounts.exceptions.custom_global_exception_handler',

    'DEFAULT_THROTTLE_CLASSES': [
            'rest_framework.throttling.AnonRateThrottle',
            'rest_framework.throttling.UserRateThrottle'
        ],

        # 3. Throttling / Rate Limiting (Added to protect OTP and Login endpoints)
        'DEFAULT_THROTTLE_RATES': {
            'otp_requests': '5/min', # Limit anon users to 5 OTP requests per minute
            'login_requests': '10/min', # Limit anon users to 10 login attempts per minute
            # FIX: RegisterView now uses its own throttle scope
            # (RegisterRateThrottle in views.py) instead of reusing
            # 'login_requests'; add its rate here.
            'register_requests': '5/min',
            'user': '100/min', # Limit authenticated users 
        },
}



# FIX (scaling bug): DRF's throttle counters use Django's default cache
# backend. Without an explicit CACHES setting, that's LocMemCache — an
# in-process dict. If you ever run more than one worker process (gunicorn
# with >1 worker, multiple containers, etc.), each process has its own
# independent throttle counter, so the real effective rate limit is
# (configured rate x number of workers), silently. For a single dev process
# this "works", but it's a false sense of security in production. Use a
# shared backend (Redis shown here) once you have more than one process.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}


# Production example (uncomment and `pip install django-redis`):
# CACHES = {
#     "default": {
#         "BACKEND": "django_redis.cache.RedisCache",
#         "LOCATION": config("REDIS_URL", default="redis://127.0.0.1:6379/1"),
#         "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient"},
#     }
# }



# Production Security Headers (Ensure these are True in production)
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'



# FIX (missing hardening): these were absent entirely. They're no-ops in
# local DEBUG (no HTTPS locally) but are the standard baseline for any
# production Django deployment served over HTTPS behind a reverse proxy.
if not DEBUG:
    SECURE_SSL_REDIRECT = True
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    # Only set this if you're actually behind a proxy (nginx/ALB) that sets
    # X-Forwarded-Proto; setting it without a trusted proxy in front is itself
    # a spoofing risk.
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')




# JWT settings for Django REST Framework Simple JWT
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60), # short lifetime for token security
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),    # user can get new Access Tokens without logging in again.
    "ROTATE_REFRESH_TOKENS": True,                  # User gets a new Refresh Token upon refresh.
    "BLACKLIST_AFTER_ROTATION": True,               # Old refresh token becomes invalid.
    "AUTH_HEADER_TYPES": ("Bearer",),               # Expected prefix in the Authorization header
}

MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware', # Keep this at the top of the middleware stack
    
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'Airbnb_Clone.urls'

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

WSGI_APPLICATION = 'Airbnb_Clone.wsgi.application'


# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# NOTE: SQLite is fine for local dev but does not handle concurrent writers
# well (it locks the whole DB file per write transaction). This codebase uses
# select_for_update() extensively (OTP verification, login attempts, 2FA,
# account deletion) — those row-locking semantics only really work correctly
# under Postgres/MySQL. Plan to move to Postgres before production.
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'


# FIX (missing settings): UserProfile.avatar is an ImageField uploading to
# "avatars/", but MEDIA_URL/MEDIA_ROOT were never defined. Without these,
# uploaded avatars have nowhere defined to be written to / served from
# (`value.url` generation and `upload_to` resolution both depend on
# MEDIA_ROOT/MEDIA_URL being set).
MEDIA_URL = 'media/'
MEDIA_ROOT = BASE_DIR / 'media'

# Default primary key field type
# REQUIRED for modern Django (3.2+) to prevent migration warnings
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# ────────────────────────────────────────── Email (SMTP) ──────────────────────────────────────────────────────────────────
# Email settings for STMP(Simple Mail Transfer Protocol)
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend" # Which mail backend to use (SMTP).
EMAIL_HOST = "smtp.gmail.com" # SMTP server address (Gmail).
EMAIL_PORT = 587  # Port for Transport Layer Security (TLS) (587)
EMAIL_USE_TLS = True # Enable TLS encryption.


EMAIL_HOST_USER = config('EMAIL_HOST_USER') # Your Gmail address (from .env).
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD') # Your Gmail App Password (from .env).
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default=EMAIL_HOST_USER)
# NOTE: DEFAULT_FROM_EMAIL is used by otp_logic/utils.py's _send_email() but
# was never defined in the settings you shared — every OTP/password-reset
# email send would have raised AttributeError at runtime.


# ─────────────────── App-specific settings (MISSING) ───────────────────
# FIX (would-crash-on-first-use bug): otp_logic/utils.py's
# get_email_context() reads settings.COMPANY_NAME, settings.SCHOOL_NAME,
# settings.FRONTEND_URL, settings.BACKEND_URL, settings.SUPPORT_EMAIL,
# settings.PRIMARY_COLOR, and services.py reads settings.OTP_EXPIRY_MINUTES —
# NONE of these existed anywhere in the settings.py you shared. The very
# first OTP email send (registration) would have raised AttributeError and
# been caught by the broad `except Exception` in _send_email(), silently
# returning False, which register_user() turns into "Unable to send
# verification email" — i.e. registration would be completely broken in a
# way that looks like an SMTP problem but is actually a missing-setting bug.
COMPANY_NAME = config('COMPANY_NAME', default='Your Company')
SCHOOL_NAME = config('SCHOOL_NAME', default='Your Platform')
FRONTEND_URL = config('FRONTEND_URL', default='http://localhost:3000')
BACKEND_URL = config('BACKEND_URL', default='http://localhost:8000')
SUPPORT_EMAIL = config('SUPPORT_EMAIL', default=EMAIL_HOST_USER)
PRIMARY_COLOR = config('PRIMARY_COLOR', default='#0d6efd')
LOGO_URL = config('LOGO_URL', default='')
OTP_EXPIRY_MINUTES = config('OTP_EXPIRY_MINUTES', default=10, cast=int)

# ─────────────────────────────── Logging ───────────────────────────────
# FIX (missing config): every file uses `logger = logging.getLogger(__name__)`
# and calls logger.info/warning/error/exception extensively (login attempts,
# OTP flows, 2FA, account deletion) — all of that was going nowhere useful
# without an explicit LOGGING dict; Django's logging defaults only surface
# WARNING+ to the console and drop most of these INFO-level audit-trail logs.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{asctime} {levelname} {name} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': config('DJANGO_LOG_LEVEL', default='INFO'),
            'propagate': False,
        },
        'accounts': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

