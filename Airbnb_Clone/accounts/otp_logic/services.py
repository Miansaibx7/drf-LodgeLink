import logging
from typing import Any, Optional, TYPE_CHECKING

from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db import transaction, IntegrityError


from ..models import (EmailOTP, PasswordResetOTP, UserProfile, UserSession,
    AuditLog, LoginAttempt, UserDevice)

from .utils import generate_otp, send_email_otp, send_password_reset_email
from ..exceptions import ServiceLayerError  # custom exception

logger = logging.getLogger(__name__)

# Type-safe dynamic user model loading
if TYPE_CHECKING:
    from django.contrib.auth.models import AbstractBaseUser
    UserType = AbstractBaseUser
else:
    UserType = get_user_model()

User = get_user_model()


# ===================================== Helper Functions =====================================
def _normalize_email(email: str) -> str:
    """ Normalize email to lowercase and strip whitespace."""
    return email.lower().strip()

def _get_user_by_email(email: str) -> UserType:
    """ Retrieve a user by email.
    Raises:
        ServiceLayerError: If no user exists. """
    email = _normalize_email(email)
    try:
        return User.objects.get(email=email)
    except User.DoesNotExist:
        logger.warning("User lookup failed for %s", email)
        raise ServiceLayerError("No account found with this email.")

def _get_user_for_update(email: str) -> UserType:
    """ Retrieve and lock a user by email in a single query. """
    email = _normalize_email(email)
    try:
        return User.objects.select_for_update().get(email=email)
    except User.DoesNotExist:
        logger.warning("Locked user lookup failed for %s", email)
        raise ServiceLayerError("No account found with this email.")
        
def _update_user_password(user: UserType, password: str) -> None:
    """ Update the user's password and save."""
    user.set_password(password)
    user.save(update_fields=["password"])

def _delete_otps_for_user(user: UserType, otp_model: Any) -> None:
    """ Delete ALL OTPs for a given user (active, expired, or blocked)."""
    # all_objects bypasses the ActiveOTPManager filter to delete everything
    otp_model.all_objects.filter(user=user).delete()

def _create_user_profile(user: UserType) -> None:
    """ Create a UserProfile for a new user if it doesn't exist."""
    UserProfile.objects.get_or_create(user=user)

def _log_audit(user: Optional[UserType], action: str, request_data: Optional[dict] = None, 
    metadata: Optional[dict] = None) -> None: 

    """ Helper to create an AuditLog entry. 
    Safely extracts IP and User-Agent from request_data if provided."""

    ip_address = request_data.get('ip_address') if request_data else None
    user_agent = request_data.get('user_agent', '') if request_data else ""

    AuditLog.objects.create(
        user=user, 
        action=action, 
        ip_address=ip_address,
        user_agent=user_agent, 
        metadata=metadata or {}
    )

def _create_user_session(user: UserType, refresh_token_jti: str, request_data: dict) -> UserSession:
    """ Create a UserSession from request data (IP, user-agent...)."""
    return UserSession.objects.create(
        user=user, refresh_token_jti=refresh_token_jti,
        ip_address=request_data.get('ip_address'), user_agent=request_data.get('user_agent', ''),
        device_name=request_data.get('device_name', ''), browser=request_data.get('browser', ''),
        operating_system=request_data.get('operating_system', ''), location=request_data.get('location', ''),
        is_active=True
    )

def _update_user_device(user: UserType, request_data: dict) -> Optional[UserDevice]:
    """ Update or create a UserDevice based on device_id (if provided)."""
    device_id = request_data.get('device_id')
    if not device_id:
        return None
    device, created = UserDevice.objects.get_or_create(
        user=user,
        device_id=device_id,
        defaults={ 'device_name': request_data.get('device_name', ''),
            'browser': request_data.get('browser', ''), 'operating_system': request_data.get('operating_system', ''),
            'trusted': False
    }   )
    device.last_login = timezone.now()
    device.save(update_fields=['last_login'])
    return device


# ===================================== OTP Creation Helpers Functions ====================================================    
@transaction.atomic
def _create_email_otp(user: Any) -> str:
    """Generate a new OTP, ensure DB is clean, and store it."""
    
    user = User.objects.select_for_update().get(pk=user.pk) # Lock the user row to prevent concurrent OTP creation
    _delete_otps_for_user(user, EmailOTP) # Delete all old OTPs
    
    raw_otp = generate_otp() # Create new OTP
    otp_obj = EmailOTP.objects.create(user=user) # Use .create() instead of get_or_create() to prevent MultipleObjectsReturned
    otp_obj.set_otp(raw_otp) # set_otp() hashes the raw OTP, resets attempts, block, and expiry timer
    return raw_otp



@transaction.atomic
def _create_password_reset_otp(user: Any) -> str:
    """Generate and store a password reset OTP."""
    
    user = User.objects.select_for_update().get(pk=user.pk) # Lock user row to prevent concurrency issues
    _delete_otps_for_user(user, PasswordResetOTP) # Clean up old OTPs
    
    raw_otp = generate_otp()# Create new OTP safely
    otp_obj = PasswordResetOTP.objects.create(user=user)
    otp_obj.set_otp(raw_otp)
    return raw_otp



# ===================================== Registration ==========================================================
def send_registration_otp(user: Any) -> bool:
    """Send an email verification OTP to a newly registered user."""
    raw_otp = _create_email_otp(user)
    return send_email_otp(email=user.email, otp=raw_otp)


@transaction.atomic
def register_user(email: str, password: str, request_data: Optional[dict] = None, **extra_fields: Any) -> User: # type: ignore
    """Create a new inactive/unverified user and send a verification OTP and create a UserProfile.
        Raises:
            ServiceLayerError: If the verification email fails to send."""
    
    email = _normalize_email(email)
    extra_fields.pop('confirm_password', None) # Remove only fields that don't exist in the User model
    extra_fields.pop('terms_accepted', None)
    try:
       # Create user with inactive/unverified status
        user = User.objects.create_user(
           email=email,
          password=password,
          is_active=False,
          is_verified=False,
          **extra_fields   # includes terms_accepted, first_name, last_name, etc.
        )
    except IntegrityError:
        logger.warning("Duplicate registration attempt raced past validation for %s", email)
        raise ServiceLayerError("User with this email already exists.")

    # Create UserProfile
    _create_user_profile(user)

    # Log registration
    _log_audit(
        user=user,
        action=AuditLog.Action.REGISTER,
        request_data=request_data # use helper function
    )

    if not send_registration_otp(user):
        logger.error("Failed to send registration OTP to %s", user.email)
        raise ServiceLayerError("Unable to send verification email. Please try again.")

    logger.info("New user registered successfully: %s", user.email)
    return user



# ==================== Login & Session ========================================================================

def authenticate_user(email: str, password: str, request_data: dict) -> User: # type: ignore
    """ Authenticate a user, check LoginAttempt blocking, increment on failure,
    and on success create UserSession and UserDevice, and log login.
    
    previously LoginSerializer.validate() ran its own account-status checks and its own call to Django's authenticate(),
    and THEN LoginView called this function again, which ran a second, independent authentication
    and its own LoginAttempt bookkeeping. Net effect: two bcrypt/argon2 hash comparisons per login request 
    real CPU cost under load). """

    email = _normalize_email(email)
    ip = request_data.get('ip_address')

    attempt = LoginAttempt.objects.filter(email=email, ip_address=ip).first() # Check if this email+IP is currently blocked
    if attempt and attempt.is_blocked():
        raise ServiceLayerError(f"Too many failed attempts. Try again after {attempt.blocked_until.strftime('%H:%M:%S')}.")
    
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        User().set_password(password)  # constant-time dummy hash comparison cost

        with transaction.atomic():
            attempt, _ = LoginAttempt.objects.get_or_create(email=email, ip_address=ip, defaults={'attempts': 0})
            attempt.increment()
        raise ServiceLayerError("Invalid email or password.")

    if not user.check_password(password):
        with transaction.atomic():
            attempt, _ = LoginAttempt.objects.get_or_create(email=email, ip_address=ip, defaults={'attempts': 0})
            attempt.increment()
        raise ServiceLayerError("Invalid email or password.")

    # Password is correct — now surface account-status errors specifically.
    # These reveal account existence to someone who already knows the correct password for that email
    if not user.is_active:
        raise ServiceLayerError("Account is inactive. Please verify your email.")
    if not user.is_verified:
        raise ServiceLayerError("Email not verified. Please check your inbox for the OTP.")

    # Success – reset attempts (delete) and create session/device
    LoginAttempt.objects.filter(email=email, ip_address=ip).delete()

    # We'll create session after token generation, but we need refresh token.
    # For now, we'll store session creation outside this function.
    # So we'll return the user and let the view handle session creation with tokens.
    
    # Log login (will be done after token generation)
    return user



@transaction.atomic
def handle_successful_login(user: User, request_data: dict, refresh_token_jti: str) -> dict: # type: ignore
    """After successful authentication (and, if applicable, 2FA), 
    create UserSession, update UserDevice, and log the login."""
    
    session = _create_user_session(user, refresh_token_jti, request_data) # Create session
    device = _update_user_device(user, request_data) # Update device

    # Log login
    _log_audit(
        user=user,
        action=AuditLog.Action.LOGIN,
        request_data=request_data, # use helper function
        metadata={'session_id': session.id}
    )

    return {'session': session, 'device': device}



# ===================================== OTP Service ====================================================================
class OTPService:
    """Handles all OTP operations using the model's built-in methods."""

    @staticmethod
    def send_email_otp(email: str, request_data: Optional[dict] = None) -> bool:
        """Generate and send a fresh email verification OTP."""

        user = _get_user_by_email(email) # Use Helper Functions 
        raw_otp = _create_email_otp(user) # Use OTP Creation Helpers Functions

        if not send_email_otp(email=user.email, otp=raw_otp):
            logger.error("Failed sending OTP to %s", user.email)
            raise ServiceLayerError("Unable to send OTP. Please try again later.")

        _log_audit(
                user=user,
                action=AuditLog.Action.OTP_SENT,
                ip_address=request_data.get('ip_address') if request_data else None,
                user_agent=request_data.get('user_agent', '') if request_data else '',
                metadata={'otp_type': 'email_verification'}
            )
        
        logger.info("Email verification OTP sent successfully to %s",user.email)
        return True
    


    @staticmethod
    @transaction.atomic
    def verify_email_otp(email: str, code: str, request_data: Optional[dict] = None) -> UserType:
        """ Verify the email OTP. Handles attempts, blocking, expiry, and deletion. """
        
        # Use Helper Functions Single query to fetch AND lock the user, preventing deadlocks
        user = _get_user_for_update(email) # Lock the user row to prevent concurrent modifications

        # Use all_objects so we can properly report if they are blocked/expired
        otp_obj = EmailOTP.all_objects.filter(user=user).order_by('-created_at').first()# Get the latest active OTP for this user

        if not otp_obj:
            raise ServiceLayerError("Invalid OTP. Please request a new one.")# No active OTP-they need to request a new one
        
        # Attempt verification this increments attempts, blocks if needed, and deletes the OTP on success.
        if not otp_obj.verify_otp(code):

            # verify_otp has already incremented attempts/blocked inside the transaction Refresh to get updated state
            otp_obj.refresh_from_db()
            if otp_obj.is_blocked:
                raise ServiceLayerError("Too many invalid attempts. Please request a new OTP.")
            if otp_obj.is_expired:
                raise ServiceLayerError("OTP has expired. Please request a new OTP.")
            raise ServiceLayerError("Invalid OTP.")

        # OTP verified and deleted by model – activate the user
        user.is_active = True
        user.is_verified = True
        user.save(update_fields=["is_active", "is_verified"])

        _log_audit(
                user=user,
                action=AuditLog.Action.EMAIL_VERIFY,
                ip_address=request_data.get('ip_address') if request_data else None,
                user_agent=request_data.get('user_agent', '') if request_data else '',
            )

        logger.info("Email verified for %s", user.email)
        return user
  


    @staticmethod
    def resend_email_otp(email: str, request_data: Optional[dict] = None) -> bool:
        """ Delete old OTPs and send a fresh one. """
        # _create_email_otp now handles the deletion, so we just call send_email_otp
        return OTPService.send_email_otp(email, request_data)


    
    @staticmethod
    def send_password_reset_otp(email: str, request_data: Optional[dict] = None) -> bool:
        """ Generate and send a password reset OTP. """

        user = _get_user_by_email(email) # Use Helper Functions
        raw_otp = _create_password_reset_otp(user)

        if not send_password_reset_email(email=user.email, otp=raw_otp):
            logger.error("Failed sending password reset OTP to %s", user.email)
            raise ServiceLayerError("Unable to send password reset OTP. Please try again later.")

        _log_audit(
                user=user,
                action=AuditLog.Action.OTP_SENT,
                ip_address=request_data.get('ip_address') if request_data else None,
                user_agent=request_data.get('user_agent', '') if request_data else '',
                metadata={'otp_type': 'password_reset'}
            )

        logger.info("Password reset OTP sent to %s", user.email)
        return True
    

        
    @staticmethod
    @transaction.atomic
    def verify_password_reset_otp(email: str, code: str, new_password: str, request_data: Optional[dict] = None) -> bool:
        """ Verify password reset OTP and update the user's password.Uses the verify_otp() for security. """

        # Lock the user row to prevent concurrent modifications
        user = _get_user_for_update(email) # Use Helper Functions Single query to fetch AND lock the user
        
        
        # Get the latest OTP (unfiltered, Use all_objects to prevent masking block/expire errors)
        otp_obj = PasswordResetOTP.all_objects.filter(user=user).order_by('-created_at').first()

        if not otp_obj:
            raise ServiceLayerError("Invalid OTP. Please request a new one.")

        if not otp_obj.verify_otp(code):
            otp_obj.refresh_from_db()
            if otp_obj.is_blocked:
                raise ServiceLayerError("Too many invalid attempts. Please request a new OTP.")
            if otp_obj.is_expired:
                raise ServiceLayerError("OTP has expired. Please request a new OTP.")
            raise ServiceLayerError("Invalid OTP.")

        _update_user_password(user, new_password) # Use Helper Functions OTP verified and deleted – update password

        _log_audit(
                user=user,
                action=AuditLog.Action.PASSWORD_RESET,
                ip_address=request_data.get('ip_address') if request_data else None,
                user_agent=request_data.get('user_agent', '') if request_data else '',
            )

        logger.info("Password reset for %s", user.email)
        return True



    @staticmethod
    @transaction.atomic
    def change_password(user: UserType, old_password: str, new_password: str, request_data: Optional[dict] = None) -> bool:
        """ Change password for an authenticated user. Validates old password and prevents reuse. """

        if not user.check_password(old_password):
            logger.warning("Invalid old password attempt for %s", user.email)
            raise ServiceLayerError("Current password is incorrect.")

        if old_password == new_password:
            raise ServiceLayerError("New password must be different from current password.")

        _update_user_password(user, new_password) # Update password using helper

        _log_audit(
            user=user,
            action=AuditLog.Action.PASSWORD_CHANGE,
            ip_address=request_data.get('ip_address') if request_data else None,
            user_agent=request_data.get('user_agent', '') if request_data else '',
        )
        
        logger.info("Password changed for %s", user.email)
        return True