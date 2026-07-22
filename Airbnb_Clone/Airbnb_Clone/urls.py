
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    # Django Admin Panel
    path("admin/", admin.site.urls),

    # Main Authentication Router (Includes Login, Register, OTP, OAuth, 2FA, Deletion)
    path("api/auth/", include("accounts.urls")),

    # SimpleJWT native endpoint for refreshing tokens
    path("api/auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
]