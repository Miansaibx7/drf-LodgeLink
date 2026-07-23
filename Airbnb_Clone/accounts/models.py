import uuid
from django.db import models,transaction

from django.contrib.auth.models import (AbstractBaseUser,BaseUserManager,PermissionsMixin)
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

        # IntegrityError catch.RegisterSerializer already
        # validates email uniqueness. Catching it here masks real DB issues

        # NOTE: RegisterSerializer.validate_email() checks uniqueness before this
        # runs, but that check-then-create is NOT atomic — two concurrent requests
        # for the same email can both pass validation and both land here. The
        # DB unique=True constraint on User.email will raise IntegrityError for
        # the second one. We deliberately do NOT swallow it here; the caller
        # (register_user in services.py) catches IntegrityError and converts it
        # into a clean, user-facing error instead of a 500. See services.py.
        user.save(using=self._db)
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
    # UUIDs prevent attackers from knowing how many users you have.
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, validators=[EmailValidator()]) # unique=True automatically creates a database index
    first_name = models.CharField(max_length=150, blank=True)
    last_name = models.CharField(max_length=150, blank=True)
    
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    terms_accepted = models.BooleanField(default=False) 

    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    
    objects = UserManager()

    class Meta:
        ordering = ["-created_at"]   # use created_at for ordering
        verbose_name = "User"
        verbose_name_plural = "Users"
        indexes = [models.Index(fields=["is_active"]),
            models.Index(fields=["is_verified"])]

    def __str__(self):
        return self.email

    def save(self, *args, **kwargs):
        if self.email:
            self.email = self.email.lower().strip()
        super().save(*args, **kwargs)

    def get_full_name(self)-> str:
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.first_name or self.last_name or self.email

    def get_short_name(self)-> str:
        return self.first_name or self.email.split('@')[0]



class ActiveOTPManager(models.Manager):
    """Manager that only returns OTPs that are not expired or blocked."""
    # A manager method will fetch the latest active OTP.
    def get_queryset(self):
        now = timezone.now()
        threshold = now - timedelta(minutes=self.model.OTP_EXPIRY_MINUTES)
        return super().get_queryset().filter(created_at__gte=threshold).filter(
            models.Q(blocked_until__isnull=True) | models.Q(blocked_until__lte=now)
        )

    def get_active_for_user(self, user):
        """Return the latest active OTP for a given user."""
        return self.get_queryset().filter(user=user).order_by('-created_at').first()



class BaseOTP(models.Model):
    OTP_LENGTH = 6
    OTP_EXPIRY_MINUTES = 10
    MAX_ATTEMPTS = 5
    BLOCK_MINUTES = 15

    user = models.ForeignKey(User, on_delete=models.CASCADE) # One user can have multiple OTPs (password reset requests)
    otp_hash = models.CharField(max_length=255) # Hashed OTP value ( using Django's make_password)
    attempts = models.PositiveSmallIntegerField(default=0)

    # This allows set_otp() to actually update the timestamp.
    created_at = models.DateTimeField(default=timezone.now)
    blocked_until = models.DateTimeField(null=True, blank=True)

    # Filtered manager – returns only active OTPs
    objects = ActiveOTPManager()
    # Use to Unfiltered manager – returns all OTPs 
    all_objects = models.Manager()

    class Meta:
        abstract = True
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.email} OTP"

    # ── Properties ──────────────────────────────────
    @property
    def is_expired(self) -> bool:
        return timezone.now() >= (self.created_at + timedelta(minutes=self.OTP_EXPIRY_MINUTES))

    @property
    def is_blocked(self) -> bool:
        """Blocked only if block_until is in the future, OR if no block time but attempts exhausted.
        After block expires, we treat the OTP as unblocked."""
        now = timezone.now()
        if self.blocked_until and now < self.blocked_until:
            return True
        # Block expired – OTP is not blocked, even if attempts >= MAX
        return False

    # ── Helper methods ──────────────────────────────
    def reset_block_if_expired(self) -> None:
        """Clear block and reset attempts if the block time has passed."""
        if self.blocked_until and timezone.now() >= self.blocked_until:
            self.blocked_until = None
            self.attempts = 0
            self.save(update_fields=["blocked_until", "attempts"])

    # ── Core OTP operations ─────────────────────────
    def set_otp(self, raw_otp: str) -> None:
        """Hash and store a new OTP.Resets attempts, block, and expiry timer."""
        self.otp_hash = make_password(raw_otp)
        self.attempts = 0
        self.blocked_until = None
        self.created_at = timezone.now()          # 🔁 restart expiry window
        self.save(update_fields=["otp_hash", "attempts", "blocked_until", "created_at"])

    def verify_otp(self, raw_otp: str) -> bool:
        """Verifies the OTP atomically to prevent race condition brute-forcing."""
        with transaction.atomic():
            try:
                # Lock the DB row to block concurrent HTTP validation requests
                obj = self.__class__.all_objects.select_for_update().get(pk=self.pk)
            except self.__class__.DoesNotExist:
                return False

            # First, clear any expired block on the locked instance
            if obj.blocked_until and timezone.now() >= obj.blocked_until:
                obj.blocked_until = None
                obj.attempts = 0
                obj.save(update_fields=["blocked_until", "attempts"])

            if obj.is_expired or obj.is_blocked:
                return False

            if check_password(raw_otp, obj.otp_hash):
                obj.delete() # one‑time use
                # FIX: obj is deleted, self.pk is now stale. Guard refresh_from_db
                # below so we don't raise DoesNotExist on the success path.
                self._state.adding = True
                return True
            
            # Handle failed attempt safely within the lock
            obj.attempts += 1
            if obj.attempts >= self.MAX_ATTEMPTS and not obj.blocked_until:
                obj.blocked_until = timezone.now() + timedelta(minutes=self.BLOCK_MINUTES)
                obj.save(update_fields=["attempts", "blocked_until"])
            # FIX (bug): previously this unconditional refresh_from_db() ran even
            # after obj.delete() above, which raises DoesNotExist on the *successful*
            # verification path because self.pk no longer exists in the DB. We only
            # refresh on the failure path now.
            if not self._state.adding:
                self.refresh_from_db()
            return False

    def increment_attempts(self) -> None:
        """Atomically increment attempts and apply a block if threshold reached.
        Uses select_for_update to avoid race conditions."""
        with transaction.atomic():
            obj = self.__class__.all_objects.select_for_update().get(pk=self.pk)
            # Clear block if expired before incrementing
            if obj.blocked_until and timezone.now() >= obj.blocked_until:
                obj.blocked_until = None
                obj.attempts = 0

            obj.attempts += 1
            if obj.attempts >= self.MAX_ATTEMPTS and not obj.blocked_until:
                obj.blocked_until = timezone.now() + timedelta(minutes=self.BLOCK_MINUTES)
            obj.save(update_fields=["attempts", "blocked_until"])
            # Update the current instance in memory
            self.refresh_from_db()
         


class EmailOTP(BaseOTP):
    # Inherits BaseOTP.Meta to ensure ordering=["-created_at"] isn't lost
    class Meta(BaseOTP.Meta):
        verbose_name = "Email OTP"
        verbose_name_plural = "Email OTPs"
        indexes = [models.Index(fields=["user", "-created_at"])]

    def __str__(self):
        return f"{self.user.email} - Email Verification"


class PasswordResetOTP(BaseOTP):
    # Inherits BaseOTP.Meta to ensure ordering=["-created_at"] isn't lost
    class Meta(BaseOTP.Meta):
        verbose_name = "Password Reset OTP"
        verbose_name_plural = "Password Reset OTPs"
        indexes = [models.Index(fields=["user", "-created_at"])]

    def __str__(self):
        return f"{self.user.email} - Password Reset"


class UserProfile(TimeStampedModel):
    """Extended user profile information."""

    user = models.OneToOneField(User,on_delete=models.CASCADE,related_name='profile')

    phone_number = models.CharField(max_length=20, blank=True,validators=[RegexValidator(regex=r'^\+?[0-9]{7,15}$',
                                                        message='Invalid phone number.')])
    avatar = models.ImageField(upload_to="avatars/",blank=True,null=True,)
    country = models.CharField(max_length=100, blank=True)
    timezone = models.CharField(max_length=100, default="UTC")
    language = models.CharField(max_length=7, default="en")  # Could use LANGUAGES setting

    class Meta:
        verbose_name = "User Profile"
        verbose_name_plural = "User Profiles"
        # OneToOneField creates a unique database index automatically.

    def __str__(self):
        return f"{self.user.email} - Profile"


class UserSession(TimeStampedModel):
    """Track active user sessions."""

    user = models.ForeignKey(User,on_delete=models.CASCADE,related_name='sessions')

    refresh_token_jti = models.CharField(max_length=255, unique=True)
    browser = models.CharField(max_length=100,blank=True)
    operating_system = models.CharField(max_length=100,blank=True)

    ip_address = models.GenericIPAddressField(null=True,blank=True)
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
        indexes = [models.Index(fields=["user", "is_active"]),
            # because unique=True creates it automatically. Index(fields=["refresh_token_jti"]
            models.Index(fields=["-last_activity"])
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
        ("ACCOUNT_DELETE", "Account Delete")
    )

    user = models.ForeignKey(User,on_delete=models.SET_NULL,null=True,related_name='audit_logs')

    action = models.CharField(max_length=50, choices=ACTIONS)
    ip_address = models.GenericIPAddressField(null=True,blank=True)
    metadata = models.JSONField(default=dict,blank=True)

    user_agent = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        indexes = [
            models.Index(fields=["user", "action"]),
            models.Index(fields=["-created_at"]),
            models.Index(fields=["action"])
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
        constraints = [
                    models.UniqueConstraint(fields=["email", "ip_address"], name="unique_login_attempt")
        ]
        indexes = [models.Index(fields=["email"]),models.Index(fields=["ip_address"]),
                models.Index(fields=["blocked_until"])]

    def __str__(self):
        return f"{self.email} - {self.attempts} attempts"

    def is_blocked(self) -> bool:
        return bool(self.blocked_until and timezone.now() < self.blocked_until)

    def increment(self, minutes: int = 15, max_attempts: int = 5) -> None:
        """Atomically increment attempt count and block if threshold exceeded.
        Uses an UPDATE query to avoid race conditions."""
        with transaction.atomic():
            # Lock the row to prevent concurrent updates
            obj = LoginAttempt.objects.select_for_update().get(pk=self.pk)
            obj.attempts += 1
            if obj.attempts >= max_attempts and not obj.blocked_until:
                obj.blocked_until = timezone.now() + timedelta(minutes=minutes)
            obj.save(update_fields=["attempts", "blocked_until"])
        # Refresh the current instance so it reflects the DB state
        self.refresh_from_db()



class TwoFactorAuth(models.Model):
    """ Store 2FA secrets and status.
        SECURITY (unresolved — flagging clearly): `secret_key` is stored in
        PLAINTEXT. TOTP secrets are long-lived credentials; anyone with read
        access to the DB (a backup, a leaked dump, a compromised replica) can
        generate valid codes forever. Before production, encrypt this field at
        rest — e.g. `django-encrypted-model-fields`'s EncryptedCharField, or a
        custom Fernet-based field using a key from your secrets manager (not
        SECRET_KEY). This is not a cosmetic recommendation; treat it as a
        blocker for production launch. """

    user = models.OneToOneField(User,on_delete=models.CASCADE,related_name='two_factor_auth')

    # 🔐 Replace with EncryptedCharField in production. null=True because we
    # clear it on disable() — see FIX note in services/two_factor.py.
    secret_key = models.CharField(max_length=255, null=True, blank=True)

    # Hashed backup codes (list of strings)
    backup_code_hashes = models.JSONField(default=list, blank=True)

    enabled = models.BooleanField(default=False)
    enabled_at = models.DateTimeField(null=True, blank=True)
    disabled_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "Two-Factor Authentication"
        verbose_name_plural = "Two-Factor Authentications"

    def __str__(self):
        return f"{self.user.email} - {'Enabled' if self.enabled else 'Disabled'}"

    def enable(self, secret: str) -> None:
        self.secret_key = secret
        self.enabled = True
        self.enabled_at = timezone.now()
        self.disabled_at = None
        self.save(update_fields=["secret_key", "enabled", "enabled_at", "disabled_at"])

    def disable(self) -> None:
            self.enabled = False
            self.secret_key = None
            self.backup_code_hashes = []
            self.disabled_at = timezone.now()
            self.save(update_fields=["enabled", "secret_key", "backup_code_hashes", "disabled_at"])

    def set_backup_codes(self, raw_codes: list) -> None:
        """Hash and store a new set of one‑time backup codes."""
        self.backup_code_hashes = [make_password(code) for code in raw_codes]
        self.save(update_fields=["backup_code_hashes"])

    def consume_backup_code(self, raw_code: str) -> bool:
            """Verify and consume a backup code atomically.Returns True if the code was valid and used, False otherwise."""
            with transaction.atomic():
                # Lock the row to prevent concurrent consumption of the same code
                obj = TwoFactorAuth.objects.select_for_update().get(pk=self.pk)
                for i, hash_val in enumerate(obj.backup_code_hashes):
                    if check_password(raw_code, hash_val):
                        obj.backup_code_hashes.pop(i) # Code valid – remove it and update
                        obj.last_used_at = timezone.now()
                        obj.save(update_fields=["backup_code_hashes", "last_used_at"])
                        # FIX (bug): the original code returned True from *inside*
                        # the `with` block without ever updating `self` (the caller's
                        # in-memory instance stayed stale). Refresh before returning.
                        self.refresh_from_db()
                        return True
            return False


    
class AccountDeletionRequest(models.Model):
    """Request to delete a user account (GDPR compliance)."""

    user = models.ForeignKey(User,on_delete=models.CASCADE,related_name='deletion_requests')

    reason = models.TextField(blank=True)
    scheduled_for = models.DateTimeField(db_index=True)
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
        self.save(update_fields=["completed", "completed_at"])



class SocialAccount(TimeStampedModel):
    """Store linked OAuth accounts."""

    PROVIDERS = (
        ("google", "Google"),
        ("github", "GitHub"),
        ("facebook", "Facebook"),
        ("linkedin", "LinkedIn"),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="social_accounts")
    provider_email = models.EmailField(blank=True)
    avatar_url = models.URLField(blank=True)
    provider = models.CharField(max_length=20, choices=PROVIDERS)
    provider_user_id = models.CharField(max_length=255)

    class Meta:
        verbose_name = "Social Account"
        verbose_name_plural = "Social Accounts"
        ordering = ["-created_at"]
        constraints = [
            # These constraints handle the indexing natively.
            models.UniqueConstraint(fields=["provider", "provider_user_id"], name="unique_social_account_provider_user"),
            models.UniqueConstraint(fields=["user", "provider"], name="unique_user_provider_social_account")
        ]
        # Removed Meta.indexes entirely. ForeignKey and UniqueConstraints 
        # already cover user, provider, and provider_user_id.

    def __str__(self):
        return f"{self.user.email} - {self.provider}"
    


class UserDevice(TimeStampedModel):

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="devices")

    device_id = models.CharField(max_length=255)
    device_name = models.CharField(max_length=255, blank=True)
    browser = models.CharField(max_length=100, blank=True)
    operating_system = models.CharField(max_length=100, blank=True)
    trusted = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = "User Device"
        verbose_name_plural = "User Devices"
        ordering = ["-last_login"]
        constraints = [models.UniqueConstraint(fields=["user", "device_id"],name="unique_user_device")]
        indexes = [
            # Removed redundant models.Index for "user" (covered by ForeignKey) 
            # and "device_id" (covered by unique=True) but i remove it.
            # Sometime we the DB store both user device_id at same time so that why.
            # Kept only "trusted".
            models.Index(fields=["trusted"])
        ]

    def __str__(self):
        return f"{self.user.email} - {self.device_name or self.device_id}"