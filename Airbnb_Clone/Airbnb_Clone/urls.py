
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("admin/", admin.site.urls),

    # Auth app URLs
    path("api/auth/", include("accounts.urls")),

    # SimpleJWT refresh token endpoint
    path("api/auth/token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
]