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
def send_email_otp(email: str, otp: str) -> bool:
    """
    Send OTP to the user's email.

    Args:
        email (str): Recipient email address.
        otp (str): Six-digit OTP.

    Returns:
        bool:
            True  -> Email sent successfully.
            False -> Failed to send email.
    """

    subject = "Email Verification OTP"

    message = f"""
Hello,

Your One-Time Password (OTP) is:

{otp}

This OTP is valid for 10 minutes.

If you did not request this OTP, please ignore this email.

Thank you.
"""
    try:
        send_mail(subject=subject, message=message, from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],fail_silently=False,)
        
        logger.info("OTP email sent successfully to %s", email)
        return True
    except Exception:
        logger.exception("Failed to send OTP email to %s", email)
        return False


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