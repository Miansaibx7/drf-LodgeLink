"""
Reusable utility functions.
Contains:
- Secure OTP generation - Email sending helpers - Email verification sender
- Password reset sender - JWT token generation """

import logging
import secrets
from typing import Any

from django.conf import settings

from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string


from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)

from rest_framework.response import Response
from ..models import User

# Common Email Context
def get_email_context() -> dict[str, Any]:
    """ Returns common template context used by every email. Keep company information in settings.py instead of
    hardcoding values throughout the project. """

    return {
        "company_name": settings.COMPANY_NAME,
        "school_name": settings.SCHOOL_NAME,
        "frontend_url": settings.FRONTEND_URL,
        "backend_url": settings.BACKEND_URL,
        "support_email": settings.SUPPORT_EMAIL,
        "primary_color": settings.PRIMARY_COLOR,
        "logo_url": getattr(settings, "LOGO_URL", ""),
    }



# Generate Secure 6-Digit OTP
def generate_otp() -> str:
    """Generate a cryptographically secure 6-digit OTP.
    Returns:
        str: Six-digit OTP as a string."""
    
    return f"{secrets.randbelow(900000) + 100000:06d}"



# Internal Email Sender
def _send_email(*,email: str,subject: str,html_template: str,text_template: str,context: dict[str, Any]) -> bool:
    """ Internal reusable email sender.
    Sends both:
        • HTML email
        • Plain text fallback
    Returns:
        True  -> Email sent successfully
        False -> Failed """

    try:
        html_content = render_to_string(html_template, context)
        text_content = render_to_string(text_template, context)

        message = EmailMultiAlternatives(subject=subject, body=text_content,
            from_email=settings.DEFAULT_FROM_EMAIL,to=[email]
        )

        message.attach_alternative(html_content, "text/html")
        message.send(fail_silently=False)

        logger.info("Email sent successfully to %s", email)
        return True

    except Exception as exc:
        logger.exception("Unable to send email to %s. Error: %s",email,exc)
        return False



# Email Verification
def send_email_otp(*, email: str, otp: str) -> bool:
    """Send email verification OTP to the registering user."""
    
    # Fetch global context keys and mix in the user-specific OTP data
    context = {
        **get_email_context(),
        "otp": otp,
        "expiry_minutes": settings.OTP_EXPIRY_MINUTES,
    }

    return _send_email(
        email=email,
        subject=f"{settings.SCHOOL_NAME} - Verify Your Email",
        html_template="accounts/emails/email_verification.html",
        text_template="accounts/emails/email_verification.txt",
        context=context
    )


# Password Reset Email
def send_password_reset_email(*, email: str, otp: str) -> bool:
    """Send password reset OTP email.
    Args:
        email: Recipient email.
        otp: Generated OTP.
    Returns:
        bool: Email sending status."""

    context = {
        **get_email_context(),
        "otp": otp,
        "expiry_minutes": settings.OTP_EXPIRY_MINUTES,
    }

    return _send_email(
        email=email,
        subject=f"{settings.SCHOOL_NAME} - Password Reset",
        html_template="accounts/emails/password_reset.html",
        text_template="accounts/emails/password_reset.txt",
        context=context,
    )



# JWT Token Generator
def get_tokens_for_user(user) -> dict[str, str]:
    """ Generate JWT tokens for a user.
    Returns:
    {
        "access": "...",
        "refresh": "...",
        "jti": "..."
    }
    The JTI is stored in UserSession so a refresh token
    can later be revoked individually. """

    refresh = RefreshToken.for_user(user)
    return {
        "access": str(refresh.access_token),
        "refresh": str(refresh),
        "jti": str(refresh["jti"]) # useful for UserSession tracking
    }



def api_success(message: str, data: dict = None, status_code: int = 200) -> Response:
    """Standardizes successful responses."""
    return Response({"success": True, "message": message, "data": data or {} }, status=status_code)