from django.db import models, IntegrityError

from django.contrib.auth.models import (AbstractBaseUser,BaseUserManager,PermissionsMixin,)
from django.core.validators import RegexValidator
from datetime import timedelta
from django.utils import timezone


class UserManager(BaseUserManager):
    """Custom manager for email authentication."""

    def create_user(self, email, password=None, **extra_fields):
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

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields['is_staff'] = True
        extra_fields['is_superuser'] = True
        extra_fields['is_verified'] = True
        extra_fields['is_active'] = True

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)



class User(AbstractBaseUser, PermissionsMixin):
    """Custom user model using email authentication."""

    username = None
    email = models.EmailField(unique=True,db_index=True,)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(auto_now_add=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    objects = UserManager()

    class Meta:
        ordering = ["-date_joined"]
        verbose_name = "User"
        verbose_name_plural = "Users"

    def __str__(self):
        return self.email



class BaseOTP(models.Model):
    """Abstract model for all OTP types."""

    OTP_LENGTH = 6
    OTP_EXPIRY_MINUTES = 10
    MAX_ATTEMPTS = 5

    user = models.OneToOneField(User,on_delete=models.CASCADE,)
    code = models.CharField(max_length=OTP_LENGTH,validators=[RegexValidator(regex=r"^\d{6}$",
                                                            message="OTP must contain exactly 6 digits.",)],)
    attempts = models.PositiveSmallIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True,)

    class Meta:
        abstract = True
        ordering = ["-created_at"]

    def __str__(self):
        return self.user.email

    @property
    def is_expired(self):
        return timezone.now() >= (self.created_at + timedelta(minutes=self.OTP_EXPIRY_MINUTES))

    @property
    def is_blocked(self):
        return self.attempts >= self.MAX_ATTEMPTS

    def increment_attempts(self):
        self.attempts += 1
        self.save(update_fields=["attempts"])

        if self.is_blocked():
          self.delete()



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
    