# accounts/urls.py

from django.urls import path

from .views import (
    RegisterView,
    LoginView,
    EmailOTPSendView,
    EmailOTPVerifyView,
    ResendEmailOTPView,
    PasswordResetOTPSendView,
    PasswordResetOTPVerifyView,
    ChangePasswordView,
    GoogleLoginView,
    GitHubLoginView,
    FacebookLoginView,
    LinkedInLoginView,
    LogoutView,
)

urlpatterns = [
#---------------------Register and Login Path--------------------------------------------------------
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
#----------------------- Email Path-------------------------------------------------------------------
    path("otp/send/", EmailOTPSendView.as_view(), name="email_otp_send"),
    path("otp/verify/", EmailOTPVerifyView.as_view(), name="email_otp_verify"),
    path("otp/resend/", ResendEmailOTPView.as_view(), name="email_otp_resend"),
#------------------------ Password Path---------------------------------------------------------------
    path("password-reset/send/",PasswordResetOTPSendView.as_view(),name="password_reset_send",),
    path("password-reset/verify/",PasswordResetOTPVerifyView.as_view(),name="password_reset_verify",),
    path("change-password/", ChangePasswordView.as_view(), name="change_password"),
#------------------------- OAuth Path--------------------------------------------------------------------
    path("oauth/google/", GoogleLoginView.as_view(), name="google_login"),
    path("oauth/github/", GitHubLoginView.as_view(), name="github_login"),
    path("oauth/facebook/", FacebookLoginView.as_view(), name="facebook_login"),
    path("oauth/linkedin/", LinkedInLoginView.as_view(), name="linkedin_login"),
#-------------------------- Logout Path-------------------------------------------------------------------
    path("logout/", LogoutView.as_view(), name="logout"),
]