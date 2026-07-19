import logging
import secrets
from typing import Dict

from django.conf import settings

from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags

from rest_framework_simplejwt.tokens import RefreshToken

logger = logging.getLogger(__name__)


# Generate Secure 6-Digit OTP
def generate_otp() -> str:
    """Generate a cryptographically secure 6-digit OTP.
    Returns:
        str: Six-digit OTP as a string."""
    
    return f"{secrets.randbelow(900000) + 100000:06d}"



# Reusable function
def _send_email(*, email: str, subject: str, html_template: str, context: dict) -> bool:
    """Send an HTML email with a plain-text fallback.
    Args:
        email: Recipient email address.
        subject: Email subject.
        html_template: Django template path.
        context: Template rendering context.
    Returns:
        bool: True if sent successfully, otherwise False."""
    
    try:
        html_content = render_to_string(html_template, context)
        text_content = strip_tags(html_content)

        message = EmailMultiAlternatives(subject=subject,body=text_content,from_email=settings.DEFAULT_FROM_EMAIL,
         to=[email])
        
        message.attach_alternative(html_content, "text/html")
        message.send(fail_silently=False)

        logger.info("Email sent successfully to %s", email)
        return True

    except Exception:
        logger.exception("Failed sending email to %s", email)
        return False



def send_email_otp(*, email: str, otp: str) -> bool:
    """Send email verification OTP.
    Args:
        email: Recipient email.
        otp: Generated OTP.
    Returns:
        bool: Email sending status."""
    
    return _send_email(email=email,subject="Verify Your Email Address",
        html_template="templates/accounts/emails/email_verification.html",
        context={
            "otp": otp,
            "expiry_minutes": 10,
            "support_email": settings.DEFAULT_FROM_EMAIL,
        }
    )



def send_password_reset_email(*, email: str, otp: str) -> bool:
    """Send password reset OTP email.
    Args:
        email: Recipient email.
        otp: Generated OTP.
    Returns:
        bool: Email sending status."""
    
    return _send_email(email=email,subject="Password Reset OTP",
        html_template="templates/accounts/emails/password_reset.html",
        context={
            "otp": otp,
            "expiry_minutes": 10,
            "support_email": settings.DEFAULT_FROM_EMAIL,
        },
    )



# Generate JWT Tokens
def get_tokens_for_user(user) -> Dict[str, str]:
    """Generate JWT access and refresh tokens for a user.
    Args:
        user: Authenticated User instance.
    Returns:
        Dict[str, str]: Dictionary containing access and refresh tokens."""
    
    refresh = RefreshToken.for_user(user)

    return {
        "refresh": str(refresh),
        "access": str(refresh.access_token),
        "jti": str(refresh["jti"]),  # useful for UserSession tracking
    }








