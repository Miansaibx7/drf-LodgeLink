import logging
from typing import Any

from django.contrib.auth import get_user_model
from django.db import transaction

from rest_framework import serializers

from ..models import EmailOTP, PasswordResetOTP
from .utils import generate_otp, send_email_otp, send_password_reset_email

from ..exceptions import ServiceLayerError  # custom exception

logger = logging.getLogger(__name__)
User = get_user_model()



def _normalize_email(email: str) -> str:
    """Normalize email to lowercase and strip whitespace."""
    return email.lower().strip()



def _create_email_otp(user: Any) -> str:
    """ Generate a new OTP, store it hashed, and reset attempts/block. Returns the raw OTP (for sending via email). """
    raw_otp = generate_otp()
    # Get or create an OTP instance for this user
    otp_obj, _ = EmailOTP.objects.get_or_create(user=user)
    # set_otp() hashes the raw OTP, resets attempts, block, and expiry timer
    otp_obj.set_otp(raw_otp)
    return raw_otp



def _create_password_reset_otp(user: Any) -> str:
    """Generate and store a password reset OTP."""
    
    raw_otp = generate_otp()
    otp_obj, _ = PasswordResetOTP.objects.get_or_create(user=user)
    otp_obj.set_otp(raw_otp)
    return raw_otp



def send_registration_otp(user: Any) -> bool:
    """Send an email verification OTP to a newly registered user."""

    raw_otp = _create_email_otp(user)
    return send_email_otp(email=user.email, otp=raw_otp)



@transaction.atomic
def register_user(email: str, password: str, **extra_fields:Any) -> Any:
    """Create a new inactive/unverified user and send a verification OTP.
    Raises:
        ServiceLayerError: If the verification email fails to send. """
    
    email = _normalize_email(email)
    # Create user with inactive/unverified status
    user = User.objects.create_user(
        email=email,
        password=password,
        is_active=False,
        is_verified=False,
        **extra_fields  # catches first_name, last_name if provided later
    )
    if not send_registration_otp(user):
        logger.error("Failed to send registration OTP to %s", user.email)
        raise ServiceLayerError("Unable to send verification email. Please try again.")
    logger.info("New user registered successfully: %s", user.email)
    return user




class OTPService:
    """Handles all OTP operations using the model's built‑in methods."""

    @staticmethod
    def send_email_otp(email: str) -> bool:
        """Generate and send a fresh email verification OTP."""

        email = _normalize_email(email)

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning("OTP requested for non‑existing email %s", email)
            raise ServiceLayerError("No account found with this email.")

        raw_otp = _create_email_otp(user)
        if not send_email_otp(email=user.email, otp=raw_otp):
            logger.error("Failed sending OTP to %s", user.email)
            raise ServiceLayerError("Unable to send OTP. Please try again later.")
        
        logger.info("OTP sent to %s", user.email)
        return True



    @staticmethod
    @transaction.atomic
    def verify_email_otp(email: str, code: str) -> Any:
        """Verify the email OTP. Uses the model's verify_otp() which handles attempts, blocking, expiry, and deletion. """
        
        email = _normalize_email(email)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning("Verification attempted for non‑existing email %s", email)
            raise ServiceLayerError("Invalid OTP.")

        # Get the latest active OTP for this user
        otp_obj = EmailOTP.objects.get_active_for_user(user)
        if not otp_obj:
            # No active OTP – they need to request a new one
            raise ServiceLayerError("Invalid OTP. Please request a new one.")

        # Attempt verification – this method increments attempts, blocks if needed,
        # and deletes the OTP on success.
        if not otp_obj.verify_otp(code):
            # verify_otp returned False – determine why
            # Refresh the object to get updated attempts/blocked_until
            otp_obj.refresh_from_db()
            if otp_obj.is_blocked:
                raise ServiceLayerError("Too many invalid attempts. Please request a new OTP.")
            if otp_obj.is_expired:
                raise ServiceLayerError("OTP has expired. Please request a new OTP.")
            raise ServiceLayerError("Invalid OTP.")

        # OTP verified and deleted – activate the user
        user.is_active = True
        user.is_verified = True
        user.save(update_fields=["is_active", "is_verified"])
        logger.info("Email verified for %s", user.email)
        return user
    

    @staticmethod
    def resend_email_otp(email: str) -> bool:
        """Delete old OTPs and send a fresh one."""

        email = _normalize_email(email)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning("Resend OTP requested for non‑existing email %s", email)
            raise ServiceLayerError("No account found with this email.")

        # Delete any existing OTPs for this user
        EmailOTP.objects.filter(user=user).delete()
        # Generate and send a new OTP
        raw_otp = _create_email_otp(user)  # this creates a new one

        if not send_email_otp(email=user.email, otp=raw_otp):
            logger.error("Failed resending OTP to %s", user.email)
            raise ServiceLayerError("Unable to resend OTP. Please try again later.")
        logger.info("OTP resent to %s", user.email)
        return True
    
    
    @staticmethod
    def send_password_reset_otp(email: str) -> bool:
        """Generate and send a password reset OTP."""

        email = _normalize_email(email)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning("Password reset requested for non‑existing email %s", email)
            raise ServiceLayerError("No account found with this email.")

        raw_otp = _create_password_reset_otp(user)

        if not send_password_reset_email(email=user.email, otp=raw_otp):
            logger.error("Failed sending password reset OTP to %s", user.email)
            raise ServiceLayerError("Unable to send password reset OTP. Please try again later.")
        
        logger.info("Password reset OTP sent to %s", user.email)
        return True


    @staticmethod
    @transaction.atomic
    def verify_password_reset_otp(email: str, code: str, new_password: str) -> bool:
        """Verify password reset OTP and update the user's password.Uses the model's verify_otp() for security. """

        email = _normalize_email(email)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            logger.warning("Password reset attempt for non‑existing email %s", email)
            raise ServiceLayerError("Invalid OTP.")

        otp_obj = PasswordResetOTP.objects.get_active_for_user(user)
        if not otp_obj:
            raise ServiceLayerError("Invalid OTP. Please request a new one.")

        if not otp_obj.verify_otp(code):
            otp_obj.refresh_from_db()
            if otp_obj.is_blocked:
                raise ServiceLayerError("Too many invalid attempts. Please request a new OTP.")
            if otp_obj.is_expired:
                raise ServiceLayerError("OTP has expired. Please request a new OTP.")
            raise ServiceLayerError("Invalid OTP.")

        # OTP verified and deleted – update password
        user.set_password(new_password)
        user.save(update_fields=["password"])
        logger.info("Password reset for %s", user.email)
        return True


    @staticmethod
    @transaction.atomic
    def change_password(user: Any, old_password: str, new_password: str) -> bool:
        """ Change password for an authenticated user. Validates old password and prevents reuse. """

        if not user.check_password(old_password):
            logger.warning("Invalid old password attempt for %s", user.email)
            raise ServiceLayerError("Current password is incorrect.")

        if old_password == new_password:
            raise ServiceLayerError("New password must be different from current password.")

        user.set_password(new_password)
        user.save(update_fields=["password"])
        logger.info("Password changed for %s", user.email)
        return True
