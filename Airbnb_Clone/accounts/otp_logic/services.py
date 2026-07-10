import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.db import transaction

from rest_framework import serializers

from ..models import EmailOTP,PasswordResetOTP
from .utils import generate_otp, send_email_otp, send_password_reset_email


logger = logging.getLogger(__name__)
User = get_user_model()


def _normalize_email(email: str) -> str:
    return email.lower().strip()


def _create_email_otp(user: Any) -> str:
    """Generate a new OTP and replace any existing OTP for the user. Returns the generated OTP."""
    otp = generate_otp()
    EmailOTP.objects.update_or_create(user=user,defaults={"code": otp,"attempts": 0,},)
    return otp


def _create_password_reset_otp(user: Any) -> str:
    """Create or replace password reset OTP."""
    otp = generate_otp()
    PasswordResetOTP.objects.update_or_create(user=user,defaults={"code": otp,"attempts": 0,})
    return otp


def send_registration_otp(user: Any) -> bool:
    """Send an email verification OTP to a newly registered user."""
    otp = _create_email_otp(user)
    email_sent = send_email_otp(email=user.email,otp=otp)

    if not email_sent:
        logger.error("Failed sending registration OTP to %s",user.email)
    return email_sent


@transaction.atomic
def register_user(serializer:Any) -> Any:
    """Create a new user and send a verification OTP.

    Raises:
        ValidationError:
            If sending the verification email fails."""

    user = serializer.save()

    if not send_registration_otp(user):
        raise serializers.ValidationError({"email": "Unable to send verification email. Please try again."})
    logger.info("New user registered successfully: %s",user.email,)
    return user


class OTPService:
    """Handles all email OTP operations."""

    @staticmethod
    def send_email_otp(email: str) -> bool:
        """Generate and send a fresh OTP."""
        email = _normalize_email(email)

        try:
            user = User.objects.get(email=email)

        except User.DoesNotExist:
            logger.warning("OTP requested for non-existing email %s",email)
            raise serializers.ValidationError({"email": "No account found with this email."})

        otp = _create_email_otp(user)
        email_sent = send_email_otp(email=user.email,otp=otp)

        if not email_sent:
            logger.error("Failed sending OTP to %s",user.email)

            raise serializers.ValidationError({"email": "Unable to send OTP. Please try again later."})
        logger.info("OTP sent successfully to %s",user.email)
        return True


    @staticmethod
    @transaction.atomic
    def verify_email_otp(email: str, code: str) -> Any:
        """Verify a user's email OTP."""

        email = _normalize_email(email)
        try:
            otp = (EmailOTP.objects.select_for_update().select_related("user").get(user__email=email,code=code))

        except EmailOTP.DoesNotExist:
            logger.warning("Invalid OTP attempt for %s",email)

            try:
                user = User.objects.get(email=email)
                latest_otp = (EmailOTP.objects.filter(user=user).order_by("-created_at").first())

                if latest_otp:
                    latest_otp.increment_attempts()

            except User.DoesNotExist:
                pass

            raise serializers.ValidationError({"code": "Invalid OTP."})

        if otp.is_blocked():
            otp.delete()
            logger.warning("OTP blocked for %s",email)
            raise serializers.ValidationError({"code": "Too many invalid attempts. Please request a new OTP."})

        if otp.is_expired():
            otp.delete()
            logger.warning("Expired OTP used by %s",email)
            raise serializers.ValidationError({"code": "OTP has expired. Please request a new OTP."})
        
        user = otp.user
        user.is_active = True
        user.is_verified = True

        user.save(update_fields=["is_active","is_verified",])
        otp.delete()
        logger.info("Email verified successfully for %s",user.email)
        return user
    
    
    @staticmethod
    def resend_email_otp(email: str) -> bool:
        """Delete the previous OTP, generate a new one, and send it."""
        email = _normalize_email(email)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning("Resend OTP requested for non-existing email %s", email)
            raise serializers.ValidationError({"email": "No account found with this email."})

        # Remove old OTP
        EmailOTP.objects.filter(user=user).delete()
        # Generate new OTP
        otp = _create_email_otp(user)

        email_sent = send_email_otp(email=user.email,otp=otp)
        if not email_sent:
            logger.error("Failed resending OTP to %s",user.email)
            raise serializers.ValidationError({"email": "Unable to resend OTP. Please try again later."})
        
        logger.info("OTP resent successfully to %s",user.email)
        return True
    

    @staticmethod
    def send_password_reset_otp(email: str) -> bool:
     """Generate and send a password reset OTP."""
     email = _normalize_email(email)
     try:
         user = User.objects.get(email=email)
     except User.DoesNotExist:
        logger.warning("Password reset requested for non-existing email %s", email)

        raise serializers.ValidationError({"email": "No account found with this email."})

     otp = _create_password_reset_otp(user)
     email_sent = send_password_reset_email(email=user.email,otp=otp,)
     
     if not email_sent:
        logger.error("Failed sending password reset OTP to %s",user.email)
        raise serializers.ValidationError({"email": "Unable to send password reset OTP. Please try again later."})
     
     logger.info("Password reset OTP sent successfully to %s", user.email,)
     return True


    @staticmethod
    @transaction.atomic
    def verify_password_reset_otp(email: str,code: str,new_password: str,) -> bool:
     """Verify password reset OTP and update the user's password."""
     
     email = _normalize_email(email)
     
     try:
        otp = (PasswordResetOTP.objects.select_for_update().select_related("user")
            .get(user__email=email,code=code))
    
     except PasswordResetOTP.DoesNotExist:
        logger.warning("Invalid password reset OTP for %s",email)

        try:
            user = User.objects.get(email=email)
            latest_otp = (PasswordResetOTP.objects.filter(user=user).order_by("-created_at").first())

            if latest_otp:
                latest_otp.increment_attempts()

        except User.DoesNotExist:
            pass

        raise serializers.ValidationError({"code": "Invalid OTP."})
     
     if otp.is_blocked():
        otp.delete()
        raise serializers.ValidationError({"code": "Too many invalid attempts. Please request a new OTP."})
     
     if otp.is_expired():
        otp.delete()
        raise serializers.ValidationError({"code": "OTP has expired. Please request a new OTP."})
     
     user = otp.user
     user.set_password(new_password)
     user.save(update_fields=["password",])
     
     otp.delete()
     logger.info("Password reset successfully for %s",user.email)
     return True
