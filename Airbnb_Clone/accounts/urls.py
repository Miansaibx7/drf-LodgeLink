
from django.urls import path

from .views import (
    RegisterView, LoginView, LogoutView,
    EmailOTPSendView, EmailOTPVerifyView, ResendEmailOTPView,
    PasswordResetOTPSendView, PasswordResetOTPVerifyView, ChangePasswordView,
    GoogleLoginView, GitHubLoginView, FacebookLoginView, LinkedInLoginView
)

# Bringing in the isolated sub_views!
from .sub_views.account_deletion import (
    AccountDeletionRequestView, AccountDeletionCancelView, AccountDeletionStatusView
)
from .sub_views.two_factor import (
    EnableTOTPView, VerifyTOTPView, DisableTOTPView
)


urlpatterns = [
    # --------------------- Register, Login & Logout ---------------------
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),

    # ----------------------- Email OTP ----------------------------------
    path("otp/send/", EmailOTPSendView.as_view(), name="email_otp_send"),
    path("otp/verify/", EmailOTPVerifyView.as_view(), name="email_otp_verify"),
    path("otp/resend/", ResendEmailOTPView.as_view(), name="email_otp_resend"),

    # ------------------------ Password Management -----------------------
    path("password-reset/send/", PasswordResetOTPSendView.as_view(), name="password_reset_send"),
    path("password-reset/verify/", PasswordResetOTPVerifyView.as_view(), name="password_reset_verify"),
    path("change-password/", ChangePasswordView.as_view(), name="change_password"),

    # ------------------------- OAuth Paths ------------------------------
    path("oauth/google/", GoogleLoginView.as_view(), name="google_login"),
    path("oauth/github/", GitHubLoginView.as_view(), name="github_login"),
    path("oauth/facebook/", FacebookLoginView.as_view(), name="facebook_login"),
    path("oauth/linkedin/", LinkedInLoginView.as_view(), name="linkedin_login"),

    # ------------------------- Two-Factor Auth (Added) ------------------
    path("2fa/enable/", EnableTOTPView.as_view(), name="2fa_enable"),
    path("2fa/verify/", VerifyTOTPView.as_view(), name="2fa_verify"),
    path("2fa/disable/", DisableTOTPView.as_view(), name="2fa_disable"),

    # ------------------------- Account Deletion (GDPR) (Added) ----------
    path("deletion/request/", AccountDeletionRequestView.as_view(), name="account_delete_request"),
    path("deletion/cancel/", AccountDeletionCancelView.as_view(), name="account_delete_cancel"),
    path("deletion/status/", AccountDeletionStatusView.as_view(), name="account_delete_status"),
]