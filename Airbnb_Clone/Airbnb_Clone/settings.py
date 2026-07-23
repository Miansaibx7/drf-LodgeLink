from pathlib import Path
from datetime import timedelta  
from decouple import config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# Allows hosts - update this with your domain when moving to production.
ALLOWED_HOSTS = []

# Allows every frontend to call your API.
# In production, you may want to change this to False and use CORS_ALLOWED_ORIGINS
CORS_ALLOW_ALL_ORIGINS = True

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

# Upgrade to Argon2. PBKDF2 is fine, but Argon2 is the 
# current industry standard against GPU-based password cracking.
# Run: pip install argon2-cffi or uv add argon2-cffi
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
        'otp_requests': '5/min',    # Limit anon users to 5 OTP requests per minute
        'login_requests': '10/min', # Limit anon users to 10 login attempts per minute
        'user': '100/min',          # Limit authenticated users 
    },
}

# Production Security Headers (Ensure these are True in production)
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'


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


# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'

# Default primary key field type
# REQUIRED for modern Django (3.2+) to prevent migration warnings
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Email settings for STMP(Simple Mail Transfer Protocol)
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend" # Which mail backend to use (SMTP).
EMAIL_HOST = "smtp.gmail.com" # SMTP server address (Gmail).
EMAIL_PORT = 587  # Port for Transport Layer Security (TLS) (587)
EMAIL_USE_TLS = True # Enable TLS encryption.


EMAIL_HOST_USER = config('EMAIL_HOST_USER')     # Your Gmail address (from .env).
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')  # Your Gmail App Password (from .env).










