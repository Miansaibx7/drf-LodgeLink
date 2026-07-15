from django.db import models, IntegrityError,transaction

from django.contrib.auth.models import (AbstractBaseUser,BaseUserManager,PermissionsMixin,)
from django.core.validators import RegexValidator, EmailValidator

from django.contrib.auth.hashers import check_password,make_password

from datetime import timedelta
from django.utils import timezone



class TimeStampedModel(models.Model):
    """Abstract model that provides created_at and updated_at timestamps."""
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True



class UserManager(BaseUserManager):
    """Custom manager for email authentication."""

    def create_user(self, email, password=None, **extra_fields)-> "User":
        if not email:
            raise ValueError("Email address is required.")

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields,)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        try:
            user.save(using=self._db)
        except IntegrityError:
           raise ValueError("A user with this email already exists.")
        return user

    def create_superuser(self, email, password=None, **extra_fields)-> "User":
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_verified', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)



class User(AbstractBaseUser, PermissionsMixin, TimeStampedModel):
    """Custom user model using email authentication."""

    username = None
    email = models.EmailField(unique=True, db_index=True, validators=[EmailValidator()])
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)

    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    
    objects = UserManager()

    class Meta:
        ordering = ["-created_at"]   # use created_at for ordering
        verbose_name = "User"
        verbose_name_plural = "Users"
        indexes = [
            models.Index(fields=["is_active"]),
            models.Index(fields=["is_verified"]),
        ]

    def __str__(self):
        return self.email



    # def block_until(self, minutes: int = 1440) -> None: # 1440 minutes = 24 hours
    #     """Block the OTP for a specified number of minutes."""
    #     self.blocked_until = timezone.now() + timedelta(minutes=minutes)
    #     self.save(update_fields=["blocked_until"])
    
    
    
class BaseOTP(models.Model):
    """
    Abstract model for all OTP types.
    Stores only a **hashed** OTP, never the raw code.
    """
    OTP_LENGTH = 6
    OTP_EXPIRY_MINUTES = 10
    MAX_ATTEMPTS = 5

    user = models.ForeignKey(User,on_delete=models.CASCADE,
        # One user can have multiple OTPs (e.g., password reset requests),
        # so we use ForeignKey instead of OneToOneField.
        # A manager method will fetch the latest active OTP.
    )
    # Hashed OTP value (e.g., using Django's make_password)
    otp_hash = models.CharField(max_length=128)
    attempts = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    blocked_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        abstract = True
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.email} OTP"

    @property
    def is_expired(self) -> bool:
        return timezone.now() >= (self.created_at + timedelta(minutes=self.OTP_EXPIRY_MINUTES))

    @property
    def is_blocked(self) -> bool:
        """Check if OTP is currently blocked, and auto-reset if block expired."""
        now = timezone.now()
        if self.blocked_until and now >= self.blocked_until:
            # Block expired – clear the block and reset attempts atomically.
            BaseOTP.objects.filter(pk=self.pk).update(blocked_until=None,attempts=0)
            self.refresh_from_db()
            return False
        if self.blocked_until and now < self.blocked_until:
            return True
        return self.attempts >= self.MAX_ATTEMPTS
    

    def set_otp(self, raw_otp: str) -> None:
        """Hash and store a new OTP, reset attempts."""
        self.otp_hash = make_password(raw_otp)
        self.attempts = 0
        self.blocked_until = None
        self.save(update_fields=["otp_hash", "attempts", "blocked_until"])

    def verify_otp(self, raw_otp: str) -> bool:
        """
        Check the raw OTP against the stored hash.
        Increment attempts on failure, reset on success.
        """
        from django.contrib.auth.hashers import check_password

        if self.is_expired or self.is_blocked:
            return False

        if check_password(raw_otp, self.otp_hash):
            # Success: delete the OTP (one-time use) or mark as used.
            self.delete()
            return True

        # Failure: increment attempts
        self.increment_attempts()
        return False

    def increment_attempts(self) -> None:
        """Atomically increment attempts and set block if needed."""
        with transaction.atomic():
            # Use F() to avoid race conditions
            updated = BaseOTP.objects.filter(pk=self.pk).update(
                attempts=models.F("attempts") + 1
            )
            if updated:
                self.refresh_from_db()
                if self.attempts >= self.MAX_ATTEMPTS and not self.blocked_until:
                    self.blocked_until = timezone.now() + timedelta(minutes=15)
                    self.save(update_fields=["blocked_until"])


class EmailOTP(BaseOTP):

    class Meta:
        verbose_name = "Email OTP"
        verbose_name_plural = "Email OTPs"

    def __str__(self):
        return f"{self.user.email} - Email Verification"



class PasswordResetOTP(BaseOTP):
    
    class Meta:
        verbose_name = "Password Reset OTP"
        verbose_name_plural = "Password Reset OTPs"

    def __str__(self):
        return f"{self.user.email} - Password Reset"


class UserProfile(TimeStampedModel):
    """Extended user profile information."""

    user = models.OneToOneField(User,on_delete=models.CASCADE,related_name='profile')

    phone_number = models.CharField(max_length=20, blank=True)
    avatar = models.ImageField(upload_to="avatars/",blank=True,null=True,)
    country = models.CharField(max_length=100, blank=True)
    timezone = models.CharField(max_length=100, default="UTC")
    language = models.CharField(max_length=7, default="en")  # Could use LANGUAGES setting

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"
        indexes = [
            models.Index(fields=["user"]),
        ]

    def __str__(self):
        return f"{self.user.email} - Profile"


class UserSession(TimeStampedModel):
    """Track active user sessions."""

    user = models.ForeignKey(User,on_delete=models.CASCADE,related_name='sessions')

    refresh_token_jti = models.CharField(max_length=255, unique=True)
    browser = models.CharField(max_length=100,blank=True)
    operating_system = models.CharField(max_length=100,blank=True)

    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    device_name = models.CharField(max_length=255, blank=True)
    location = models.CharField(max_length=255,blank=True)

    last_activity = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    login_at = models.DateTimeField(auto_now_add=True)
    logout_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "User Session"
        verbose_name_plural = "User Sessions"
        indexes = [
            models.Index(fields=["user", "is_active"]),
            models.Index(fields=["refresh_token_jti"]),
            models.Index(fields=["-last_activity"]),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.device_name or 'Unknown Device'}"

    def logout(self)-> None:
        """Mark session as inactive and set logout time."""
        self.is_active = False
        self.logout_at = timezone.now()
        self.save(update_fields=["is_active", "logout_at"])


class AuditLog(models.Model):
    """Log all important user actions."""

    ACTIONS = (
        ("REGISTER", "Register"),
        ("LOGIN", "Login"),
        ("LOGOUT", "Logout"),
        ("EMAIL_VERIFY", "Email Verify"),
        ("OTP_SENT", "OTP Sent"),
        ("PASSWORD_RESET", "Password Reset"),
        ("PASSWORD_CHANGE", "Password Change"),
        ("OAUTH_LOGIN", "OAuth Login"),
        ("2FA_ENABLED", "2FA Enabled"),
        ("2FA_DISABLED", "2FA Disabled"),
        ("ACCOUNT_DELETE", "Account Delete"),
    )

    user = models.ForeignKey(User,on_delete=models.SET_NULL,null=True,related_name='audit_logs')

    action = models.CharField(max_length=50, choices=ACTIONS)
    ip_address = models.GenericIPAddressField()
    metadata = models.JSONField(default=dict,blank=True)

    user_agent = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        indexes = [
            models.Index(fields=["user", "action"]),
            models.Index(fields=["-created_at"]),
            models.Index(fields=["action"]),
        ]

    def __str__(self):
        return f"{self.user.email if self.user else 'Anonymous'} - {self.action} at {self.created_at}"



class LoginAttempt(models.Model):
    """Track failed login attempts per email and IP."""

    email = models.EmailField(db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    attempts = models.PositiveIntegerField(default=0)
    blocked_until = models.DateTimeField(null=True, blank=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Login Attempt"
        verbose_name_plural = "Login Attempts"
        ordering = ["-updated_at"]
        constraints = [models.UniqueConstraint(
                fields=["email", "ip_address"],
                name="unique_login_attempt",)]
        indexes = [models.Index(fields=["email"]),models.Index(fields=["ip_address"]),
                models.Index(fields=["blocked_until"])]

    def __str__(self):
        return f"{self.email} - {self.attempts} attempts"

    def is_blocked(self) -> bool:
        return bool(self.blocked_until and timezone.now() < self.blocked_until)

    def increment(self, minutes: int = 15, max_attempts: int = 5) -> None:
        """Increment attempt count and block if threshold exceeded."""
        self.attempts += 1
        if self.attempts >= max_attempts:
            self.blocked_until = timezone.now() + timedelta(minutes=minutes)
        self.save()

class TwoFactorAuth(models.Model):
    """Store 2FA secrets and status."""

    user = models.OneToOneField(User,on_delete=models.CASCADE,related_name='two_factor_auth')

    secret_key = models.CharField(max_length=255)
    backup_codes = models.JSONField(default=list,blank=True)
    

    enabled = models.BooleanField(default=False)
    enabled_at = models.DateTimeField(null=True, blank=True)
    disabled_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True,blank=True)

    class Meta:
        verbose_name = "Two-Factor Authentication"
        verbose_name_plural = "Two-Factor Authentications"

    def __str__(self):
        return f"{self.user.email} - {'Enabled' if self.enabled else 'Disabled'}"

    def enable(self, secret: str)-> None:
        self.secret_key = secret
        self.enabled = True
        self.enabled_at = timezone.now()
        self.disabled_at = None
        self.save()

    def disable(self)-> None:
        self.enabled = False
        self.disabled_at = timezone.now()
        self.save()


class AccountDeletionRequest(models.Model):
    """Request to delete a user account (GDPR compliance)."""

    user = models.ForeignKey(User,on_delete=models.CASCADE,related_name='deletion_requests')

    reason = models.TextField(blank=True)
    scheduled_for = models.DateTimeField()
    completed = models.BooleanField(default=False)
    completed_at = models.DateTimeField(null=True, blank=True)
    cancelled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Account Deletion Request"
        verbose_name_plural = "Account Deletion Requests"
        indexes = [
            models.Index(fields=["scheduled_for"]),
            models.Index(fields=["completed"]),
        ]

    def __str__(self):
        return f"{self.user.email} - Deletion scheduled for {self.scheduled_for}"

    def complete(self)-> None:
        """Mark the deletion request as completed."""
        self.completed = True
        self.completed_at = timezone.now()
        self.save()



class SocialAccount(TimeStampedModel):
    """Store linked OAuth accounts."""

    PROVIDERS = (
        ("google", "Google"),
        ("github", "GitHub"),
        ("facebook", "Facebook"),
        ("linkedin", "LinkedIn"),
    )

    user = models.ForeignKey(User,on_delete=models.CASCADE,related_name="social_accounts")

    provider_email = models.EmailField(blank=True)
    avatar_url = models.URLField(blank=True)
    provider = models.CharField(max_length=20, choices=PROVIDERS, db_index=True)
    provider_user_id = models.CharField(max_length=255, db_index=True)

    class Meta:
        verbose_name = "Social Account"
        verbose_name_plural = "Social Accounts"
        ordering = ["-created_at"]
        constraints = [models.UniqueConstraint(
                fields=["provider", "provider_user_id"],
                name="unique_social_account_provider_user")]
        indexes = [models.Index(fields=["provider"]),
            models.Index(fields=["provider_user_id"]),
            models.Index(fields=["user"])]

    def __str__(self):
        return f"{self.user.email} - {self.provider}"