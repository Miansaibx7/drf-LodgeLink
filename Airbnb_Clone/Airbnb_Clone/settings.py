from pathlib import Path
from decouple import config

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = config('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
# Allows 
ALLOWED_HOSTS = []
# Allows every frontend to call your API.
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

    'rest_framework',
    'rest_framework_simplejwt',
    'rest_framework_simplejwt.token_blacklist',
    'corsheaders',


    'accounts',
]

# Every API checks JWT automatically.
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES":(
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES":(
        "rest_framework.permissions.IsAuthenticated",
    ),
}

# JWT settings for Django REST Framework Simple JWT
from datetime import timedelta 
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes = 60), # short lifetime for token security
    "REFRESH_TOKEN_LIFETIME" : timedelta(days = 7), # user can get new Access Tokens without logging in again. After 7 days, they must re‑authenticate.
    "ROTATE_REFRESH_TOKENS" : True, # Every time the user refreshes their Access Token, they also get a new Refresh Token.
    "BLACKLIST_AFTER_ROTATION" : True, #  New Refresh Token is issued, the old one becomes invalid.
    "AUTH_HEADER_TYPES" : ("Bearer",), # Expected prefix in the Authorization header
}


MIDDLEWARE = [
    'corsheaders.middleware.CorsMiddleware',

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

# Email settings for STMP(Simple Mail Transfer Protocol)
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend" # Which mail backend to use (SMTP).
EMAIL_HOST = "smtp.gmail.com" # SMTP server address (Gmail).
EMAIL_PORT = 587  # Port for Transport Layer Security (TLS) (587)
EMAIL_USE_TLS = True # Enable TLS encryption.


EMAIL_HOST_USER = config('EMAIL_HOST_USER')     # Your Gmail address (from .env).
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')  # Your Gmail App Password (from .env).

