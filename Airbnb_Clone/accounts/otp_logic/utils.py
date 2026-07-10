import logging
import secrets

from django.conf import settings
from django.core.mail import send_mail
from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)

# Generate Secure 6-Digit OTP
def generate_otp() -> str:
    """
    Generate a cryptographically secure 6-digit OTP.
    Returns:
        str: Six-digit OTP.
    """
    return str(secrets.randbelow(900000) + 100000)


# Send OTP Email
def _send_email(*,email: str,subject: str, message: str) -> bool:
    """Generic email sender."""
    try:
        send_mail(subject=subject, message=message, from_email=settings.DEFAULT_FROM_EMAIL,
         recipient_list=[email],fail_silently=False)

        logger.info("Email sent successfully to %s", email)
        return True
    
    except Exception:
        logger.exception("Failed sending email to %s",email)
        return False


def send_email_otp(*, email: str, otp: str) -> bool:
    """Send account verification OTP."""

    subject = "Verify Your Email Address"
    message = f""" Hello, Thank you for registering. Your email verification OTP is: {otp} This OTP is valid for 10 minutes.
    If you did not request this OTP, please ignore this email. Thank you."""

    return _send_email(email=email, subject=subject, message=message)


# Generate JWT Tokens
def get_tokens_for_user(user) -> dict:
    """
    Generate JWT Access and Refresh tokens.

    Args:
        user: Authenticated User instance.

    Returns:
        dict: Access and Refresh tokens.
    """
    refresh = RefreshToken.for_user(user)
    return {"refresh": str(refresh), "access": str(refresh.access_token),}


def send_password_reset_email(*, email: str, otp: str) -> bool:
    """Send password reset OTP."""

    subject = "Password Reset OTP"
    message = f""" Hello, We received a request to reset your password. Your password reset OTP is: {otp}
    This OTP is valid for 10 minutes. If you did not request a password reset, please ignore this email. Thank you."""

    return _send_email(email=email, subject=subject, message=message)


