from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model

from django.contrib.auth.password_validation import validate_password
from typing import Any
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction # Essential for atomic database commits during OAuth registration

from django.core.validators import RegexValidator
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
import requests

from .models import SocialAccount, UserDevice, UserProfile
from django.core.files.uploadedfile import UploadedFile

User = get_user_model()



class RegisterSerializer(serializers.ModelSerializer):
    """Handles user registration with email, password, and confirmation.
       Password validation includes checks against the email address."""
    
    email = serializers.EmailField(required=True)
    # Removed `validators=[validate_password]` from here. It is now handled in `validate()` 
    # to allow attribute similarity checks against the email.
    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)
    confirm_password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)

    class Meta:
        model= User
        fields = ('email','password','confirm_password', 'terms_accepted')

# validate email uniqueness and password confirmation
    def validate_email(self, value: str) -> str:
            """ NOTE: this uniqueness check is advisory only — it narrows the error
            surface for the common case, but it is NOT race-safe by itself
            (check-then-create). Two simultaneous registrations for the same
            email can both pass this check. The actual guarantee is the DB
            unique constraint on User.email; services.register_user() catches
            the resulting IntegrityError and turns it into a clean error. Do
            not remove that try/except thinking this validator makes it
            redundant."""
            value = value.lower().strip()
            if User.objects.filter(email=value).exists():
                raise serializers.ValidationError({"email": "User with this email already exists."})
            return value

    def validate_terms_accepted(self, value: bool) -> bool:
        """Require acceptance of Terms of Service."""
        if not value:
            raise serializers.ValidationError("You must accept the Terms of Service.")
        return value

# validate password confirmation
    def validate(self, attrs: dict) -> dict:
        """Validate password confirmation and password strength."""
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        if password != confirm_password:
            raise serializers.ValidationError({"confirm_password": "Password fields didn't match."})
        
        # Validate password against a dummy user so that similarity to email is checked
        user_instance = User(email=attrs.get('email'))
        try:
            validate_password(password, user=user_instance)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)})

        return attrs

# create user and set is_active and is_verified to False  
    def create(self, validated_data: dict) -> Any:
        """Create a new user with inactive and unverified status."""
        """ NOTE: actual user creation now happens in services.register_user(),
        which wraps this in a transaction and handles the profile creation,
        audit log, OTP dispatch, and the IntegrityError race described above.
        RegisterView calls the service directly rather than serializer.save(),
        so this create() is kept only for completeness / any code that still
        calls serializer.save() directly (e.g. tests, admin tooling). """
       # Added None fallback to prevent KeyErrors
        validated_data.pop("confirm_password", None)
        validated_data.pop("terms_accepted", None)  # not a model field
        user = User.objects.create_user(**validated_data,
        is_active = False,  # Set the user as inactive until email verification
        is_verified = False # Set the user as unverified until email verification
        )
        return user
    
    

class LoginSerializer(serializers.Serializer):
    """Authenticates user with email and password.Provides specific error messages for inactive/unverified accounts
    without leaking account existence."""

    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)

    def validate(self, attrs: dict) -> dict:
        email = attrs.get('email','').lower().strip()
        password = attrs.get('password')
        #  Django's default `authenticate()` immediately returns None if `is_active=False`.
        # We must check the user's database status before calling authenticate() to give 
        # accurate error messages about verification.
        try:
            user_obj = User.objects.get(email=email)
            if not user_obj.is_active:
                raise serializers.ValidationError({"detail": "Account is inactive. Please verify your email."})
            if not getattr(user_obj, 'is_verified', True):
                raise serializers.ValidationError({"detail": "Email not verified. Please check your inbox for the OTP."})
        except User.DoesNotExist:
            pass  # Suppress error to mask account enumeration vectors during auth processing

        user = authenticate(request=self.context.get('request'), email=email, password=password)
        if not user:
            raise serializers.ValidationError({"detail": "Invalid email or password."})

        attrs['user'] = user
        return attrs   


class BaseOTPSendSerializer(serializers.Serializer):
    """Base serializer for sending OTPs – ensures email exists."""

    email = serializers.EmailField(required=True)

    def validate_email(self, value: str) -> str:
        value = value.lower().strip()
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No account found with this email.")
        return value

class EmailOTPSendSerializer(BaseOTPSendSerializer):
    """Send OTP for email verification."""
    pass

class EmailOTPVerifySerializer(serializers.Serializer):
    """Verify email OTP."""

    email = serializers.EmailField(required=True)
    code = serializers.CharField(max_length=6,min_length=6,required=True,
        validators=[RegexValidator(r'^\d{6}$', 'OTP must be exactly 6 digits.')])
    
    def validate_email(self, value: str) -> str:
        # Added email sanitization to guarantee query matching in verification workflows
        return value.lower().strip()
    
class ResendEmailOTPSerializer(BaseOTPSendSerializer):
    """Resend email verification OTP."""
    pass

class PasswordResetOTPSendSerializer(BaseOTPSendSerializer):
    """Send OTP for password reset."""
    pass   


       
class PasswordResetOTPVerifySerializer(serializers.Serializer):
    """Verify password reset OTP and set new password.Validates password strength and prevents password reuse."""

    email = serializers.EmailField(required=True)
    code = serializers.CharField(max_length=6, min_length=6,required=True,
        validators=[RegexValidator(r'^\d{6}$', 'OTP must be exactly 6 digits.')]
    )
    # Moved validate_password to the validate() method below
    new_password = serializers.CharField(write_only=True,required=True,trim_whitespace=False)
    confirm_password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)

    def validate(self, attrs: dict) -> dict:
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')
        if new_password != confirm_password:
            raise serializers.ValidationError({"new_password": "Passwords don't match."})

        email = attrs.get('email', '').lower().strip()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "No account found with this email."})

        # Validate password strength
        try:
            validate_password(new_password, user=user)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})

        # Prevent password reuse
        if user.check_password(new_password):
            raise serializers.ValidationError({"new_password": "New password cannot be the same as the current password."})
        
        attrs['email'] = email  # store normalized email for later use
        return attrs 
    


class ChangePasswordSerializer(serializers.Serializer):
    """Allows authenticated user to change their password.Validates old password, new password strength, and avoids reuse."""
  
    old_password = serializers.CharField(write_only=True, trim_whitespace=False)
    # Moved validate_password to the validate() method below
    new_password = serializers.CharField(write_only=True,trim_whitespace=False)
    confirm_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate_old_password(self, value: str) -> str:
        request = self.context.get("request")
        if request is None:
            raise serializers.ValidationError("Request context is required.")
        user = request.user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate(self, attrs: dict) -> dict:
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})

        if attrs["old_password"] == attrs["new_password"]:
            raise serializers.ValidationError({"new_password": "New password cannot be the same as the old password."})
        #  Validate the new password against the *actual* logged-in user instance
        user = self.context['request'].user
        try:
            validate_password(attrs['new_password'], user=user)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})  
        return attrs

    def save(self)-> Any:
        request = self.context.get("request")
        if request is None:
            raise serializers.ValidationError("Request context is required.")
        user = request.user
        user.set_password(self.validated_data["new_password"])
        user.save(update_fields=["password"])
        return user



# OAUTH LOGIN
class BaseOAuthLoginSerializer(serializers.Serializer):
    """Base serializer for OAuth login.Subclasses must set `provider` and implement `get_user_info()`."""

    access_token = serializers.CharField(required=True)
    provider = None  # Must be overridden

    def _split_name(self, full_name: str) -> tuple[str, str]:
        """Split full name into first and last name."""
        full_name = full_name.strip()
        if not full_name:
            return "", ""
        parts = full_name.split(maxsplit=1)
        return parts[0], parts[1] if len(parts) > 1 else ""

    def validate(self, attrs: dict) -> dict:

        if not self.provider:
            raise serializers.ValidationError({"detail": "Provider not configured."})
        
        access_token = attrs.get('access_token')
        user_info = self.get_user_info(access_token)

        if not user_info:
            raise serializers.ValidationError({"detail": "Invalid or expired access token."})

        email = user_info.get("email")
        if not email:
            raise serializers.ValidationError({"detail": "Email not provided by provider."})
            
        email = email.lower().strip()
        provider_user_id = user_info.get('id')
        if not provider_user_id:
            raise serializers.ValidationError({"detail": "Provider user ID not provided."})

        full_name = user_info.get('name', '').strip()
        first_name, last_name = self._split_name(full_name)

        # Use atomic transaction to ensure consistency
        with transaction.atomic():
            try:
                user = User.objects.get(email=email)
                update_fields = []

                # Update name if missing
                if not user.first_name and first_name:
                    user.first_name = first_name
                    update_fields.append("first_name")  
                if not user.last_name and last_name:
                    user.last_name = last_name
                    update_fields.append("last_name")

                # Activate and verify the user if not already    
                if not user.is_active:
                    user.is_active = True
                    update_fields.append("is_active")
                if not getattr(user, 'is_verified', True):
                    user.is_verified = True
                    update_fields.append("is_verified")
                
                # Call save() exactly ONCE for the existing user
                if update_fields:
                    user.save(update_fields=update_fields)

            except User.DoesNotExist:
                # Use first_name and last_name variable
                user = User(
                    email=email, 
                    first_name=first_name, 
                    last_name=last_name,
                    is_active=True,
                    is_verified=True
                )
                user.set_unusable_password()
                user.save()

            # Create or update SocialAccount
            social_account, created = SocialAccount.objects.get_or_create(user=user,
                provider=self.provider,defaults={'provider_user_id': provider_user_id, 'provider_email': email}
            )
            # Update if fields changed (for existing records)
            soc_update_fields = []
            if not created:
                if social_account.provider_user_id != provider_user_id:
                    social_account.provider_user_id = provider_user_id
                    soc_update_fields.append("provider_user_id")

                if social_account.provider_email != email:
                    social_account.provider_email = email
                    soc_update_fields.append("provider_email")

                if soc_update_fields:
                    social_account.save(update_fields=soc_update_fields)

        attrs['user'] = user
        return attrs


    def get_user_info(self, access_token: str) -> dict:
        """Override in subclass to fetch user info from specific provider."""
        raise NotImplementedError("Subclasses must implement get_user_info()")



class GoogleLoginSerializer(BaseOAuthLoginSerializer):

    provider = "google"

    def get_user_info(self, access_token: str) -> dict:
        url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            # Ensure email is verified by Google
            if not data.get('email_verified'):
                raise serializers.ValidationError({"detail": "Google email address is not verified."})
            
            return {
                'email': data.get('email'),
                'name': data.get('name'),
                'id': data.get('id'),      # Google user ID
            }
        except requests.exceptions.RequestException as exc:
            raise serializers.ValidationError(f"OAuth provider error: {str(exc)}")        



class GitHubLoginSerializer(BaseOAuthLoginSerializer):
    
    provider = "github"

    def get_user_info(self, access_token: str) -> dict:
        url = 'https://api.github.com/user'
        headers = {'Authorization': f'Bearer {access_token}','Accept': 'application/json'}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            # GitHub may not always return email; fetch emails separately if needed
            email = data.get('email')
            if not email:
                email_response = requests.get('https://api.github.com/user/emails', headers=headers, timeout=10)
                email_response.raise_for_status()
                emails = email_response.json()
                # Pick the first verified primary email
                primary_email = next((e for e in emails if e.get('primary') and e.get('verified')), None)
                email = primary_email.get('email') if primary_email else None

            return {
                'email': email,
                'name': data.get('name') or data.get('login'),
                'id': str(data.get('id')),   # GitHub user ID as string
            }
        except requests.exceptions.RequestException as exc:
            raise serializers.ValidationError(f"OAuth provider error: {str(exc)}")



class FacebookLoginSerializer(BaseOAuthLoginSerializer):

    provider = "facebook"

    def get_user_info(self, access_token: str) -> dict:
        url = f'https://graph.facebook.com/me?fields=id,name,email&access_token={access_token}'

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            return {
                'email': data.get('email'),
                'name': data.get('name'),
                'id': data.get('id'),      # Facebook user ID
            }
        except requests.exceptions.RequestException as exc:
            raise serializers.ValidationError(f"OAuth provider error: {str(exc)}")



class LinkedInLoginSerializer(BaseOAuthLoginSerializer):
    
    provider = "linkedin"

    def get_user_info(self, access_token: str) -> dict:
        url = "https://api.linkedin.com/v2/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.get(url,headers=headers,timeout=10)
            response.raise_for_status()
            data = response.json()

            return {
                'email': data.get('email'),
                'name': data.get('name'),
                'id': data.get('sub')     # LinkedIn uses 'sub' for user ID
            }
        except requests.exceptions.RequestException as exc:
            raise serializers.ValidationError(f"OAuth provider error: {str(exc)}")



class LogoutSerializer(serializers.Serializer):
    """Blacklist the refresh token."""

    refresh = serializers.CharField()

    def validate_refresh(self, value: str) -> str:
        try:
            RefreshToken(value)
        except TokenError:
            raise serializers.ValidationError("Invalid refresh token.")
        return value

    def save(self)-> None:
        try:
            RefreshToken(self.validated_data["refresh"]).blacklist()
        except TokenError:
            pass



class RefreshTokenSerializer(serializers.Serializer):
    """Validate a refresh token (used for token refresh endpoint)."""
    refresh = serializers.CharField()

    def validate(self, attrs: dict) -> dict:
        try:
            RefreshToken(attrs["refresh"])
        except TokenError:
            raise serializers.ValidationError({"refresh": "Invalid refresh token."})
        return attrs
    


class UserDeviceSerializer(serializers.ModelSerializer):
    """Read‑only serializer for user devices."""

    class Meta:
        model = UserDevice
        fields = (
            "id",
            "device_id",
            "device_name",
            "browser",
            "operating_system",
            "trusted",
            "last_login",
        )
        read_only_fields = fields



class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile.Includes avatar validation (size and content type)."""

    class Meta:
        model = UserProfile
        fields = (
            "phone_number",
            "avatar",
            "country",
            "timezone",
            "language",
        )
        extra_kwargs = {
            "phone_number": {"required": False},
            "avatar": {"required": False, "allow_null": True},
            "country": {"required": False},
            "timezone": {"required": False},
            "language": {"required": False}
        }

    # Avatar file size
    def validate_avatar(self, value: UploadedFile) -> UploadedFile:
        """Validate avatar file size and type."""
        if not value:
            return value

        # Max 2 MB
        if value.size > 2 * 1024 * 1024:
            raise serializers.ValidationError("Avatar size must not exceed 2 MB.")

        allowed_types = {"image/jpeg","image/png","image/webp",}

        if getattr(value, 'content_type', None) not in allowed_types:
            raise serializers.ValidationError({"avatar": "Only JPEG, PNG, and WEBP images are allowed."})
        
        return value
    


class SocialAccountSerializer(serializers.ModelSerializer):
    """Read‑only serializer for social accounts."""
    class Meta:
        model = SocialAccount
        fields = (
            "id",
            "provider",
            "provider_email",
            "avatar_url",
            "created_at",
        )
        read_only_fields = fields 



class TwoFactorVerifySerializer(serializers.Serializer):
    otp_code = serializers.CharField(max_length=6, min_length=6)

class TwoFactorLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    totp_code = serializers.CharField(max_length=6, min_length=6)   














class LoginSerializer(serializers.Serializer):
    """
    Field-level validation only.

    FIX (architecture bug): the previous version authenticated the user
    *inside* the serializer via Django's authenticate(), and then LoginView
    called services.authenticate_user() again — running two full password
    hash comparisons (expensive, by design) and two separate, inconsistent
    brute-force paths (LoginAttempt tracking only happened in the service
    call). Authentication, account-status checks, and brute-force tracking
    now live in ONE place: services.authenticate_user(). The serializer only
    validates that the fields are present.
    """

    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)

    def validate_email(self, value: str) -> str:
        return value.lower().strip()


class BaseOTPSendSerializer(serializers.Serializer):
    """Base serializer for sending OTPs – ensures email exists."""

    email = serializers.EmailField(required=True)

    def validate_email(self, value: str) -> str:
        value = value.lower().strip()
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No account found with this email.")
        return value


class EmailOTPSendSerializer(BaseOTPSendSerializer):
    pass


class EmailOTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(
        max_length=6, min_length=6, required=True,
        validators=[RegexValidator(r'^\d{6}$', 'OTP must be exactly 6 digits.')]
    )

    def validate_email(self, value: str) -> str:
        return value.lower().strip()


class ResendEmailOTPSerializer(BaseOTPSendSerializer):
    pass


class PasswordResetOTPSendSerializer(BaseOTPSendSerializer):
    pass


class PasswordResetOTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(
        max_length=6, min_length=6, required=True,
        validators=[RegexValidator(r'^\d{6}$', 'OTP must be exactly 6 digits.')]
    )
    new_password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)
    confirm_password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)

    def validate(self, attrs: dict) -> dict:
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')
        if new_password != confirm_password:
            raise serializers.ValidationError({"new_password": "Passwords don't match."})

        email = attrs.get('email', '').lower().strip()
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "No account found with this email."})

        try:
            validate_password(new_password, user=user)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})

        if user.check_password(new_password):
            raise serializers.ValidationError(
                {"new_password": "New password cannot be the same as the current password."}
            )

        attrs['email'] = email
        return attrs


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, trim_whitespace=False)
    new_password = serializers.CharField(write_only=True, trim_whitespace=False)
    confirm_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate_old_password(self, value: str) -> str:
        request = self.context.get("request")
        if request is None:
            raise serializers.ValidationError("Request context is required.")
        user = request.user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate(self, attrs: dict) -> dict:
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})

        if attrs["old_password"] == attrs["new_password"]:
            raise serializers.ValidationError(
                {"new_password": "New password cannot be the same as the old password."}
            )
        user = self.context['request'].user
        try:
            validate_password(attrs['new_password'], user=user)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})
        return attrs

    def save(self) -> Any:
        request = self.context.get("request")
        if request is None:
            raise serializers.ValidationError("Request context is required.")
        user = request.user
        user.set_password(self.validated_data["new_password"])
        user.save(update_fields=["password"])
        return user


# ─────────────────────────── OAuth Login ───────────────────────────

class BaseOAuthLoginSerializer(serializers.Serializer):
    """Base serializer for OAuth login. Subclasses set `provider` and implement `get_user_info()`."""

    access_token = serializers.CharField(required=True)
    provider = None

    def _split_name(self, full_name: str) -> tuple[str, str]:
        full_name = full_name.strip()
        if not full_name:
            return "", ""
        parts = full_name.split(maxsplit=1)
        return parts[0], parts[1] if len(parts) > 1 else ""

    def validate(self, attrs: dict) -> dict:
        if not self.provider:
            raise serializers.ValidationError({"detail": "Provider not configured."})

        access_token = attrs.get('access_token')
        user_info = self.get_user_info(access_token)

        if not user_info:
            raise serializers.ValidationError({"detail": "Invalid or expired access token."})

        email = user_info.get("email")
        if not email:
            raise serializers.ValidationError({"detail": "Email not provided by provider."})

        email = email.lower().strip()
        provider_user_id = user_info.get('id')
        if not provider_user_id:
            raise serializers.ValidationError({"detail": "Provider user ID not provided."})

        full_name = user_info.get('name', '').strip()
        first_name, last_name = self._split_name(full_name)

        with transaction.atomic():
            try:
                # FIX (concurrency): lock the row so two near-simultaneous OAuth
                # callbacks for the same user (e.g. double-click, retried
                # webview) can't both run the update logic and race on
                # update_fields.
                user = User.objects.select_for_update().get(email=email)
                update_fields = []

                if not user.first_name and first_name:
                    user.first_name = first_name
                    update_fields.append("first_name")
                if not user.last_name and last_name:
                    user.last_name = last_name
                    update_fields.append("last_name")

                if not user.is_active:
                    user.is_active = True
                    update_fields.append("is_active")
                if not getattr(user, 'is_verified', True):
                    user.is_verified = True
                    update_fields.append("is_verified")

                if update_fields:
                    user.save(update_fields=update_fields)

            except User.DoesNotExist:
                user = User(
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    is_active=True,
                    is_verified=True,
                )
                user.set_unusable_password()
                user.save()

            social_account, created = SocialAccount.objects.get_or_create(
                user=user, provider=self.provider,
                defaults={'provider_user_id': provider_user_id, 'provider_email': email}
            )
            soc_update_fields = []
            if not created:
                if social_account.provider_user_id != provider_user_id:
                    social_account.provider_user_id = provider_user_id
                    soc_update_fields.append("provider_user_id")

                if social_account.provider_email != email:
                    social_account.provider_email = email
                    soc_update_fields.append("provider_email")

                if soc_update_fields:
                    social_account.save(update_fields=soc_update_fields)

        attrs['user'] = user
        return attrs

    def get_user_info(self, access_token: str) -> dict:
        raise NotImplementedError("Subclasses must implement get_user_info()")


class GoogleLoginSerializer(BaseOAuthLoginSerializer):
    provider = "google"

    def get_user_info(self, access_token: str) -> dict:
        url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            if not data.get('email_verified'):
                raise serializers.ValidationError({"detail": "Google email address is not verified."})

            return {
                'email': data.get('email'),
                'name': data.get('name'),
                'id': data.get('id'),
            }
        except requests.exceptions.RequestException as exc:
            raise serializers.ValidationError(f"OAuth provider error: {str(exc)}")
        except ValueError:
            # FIX: response.json() raises ValueError on malformed/non-JSON bodies
            # (e.g. provider outage returning an HTML error page). The original
            # code only caught RequestException, so this would surface as an
            # unhandled 500 instead of a clean 400.
            raise serializers.ValidationError({"detail": "Invalid response from Google."})


class GitHubLoginSerializer(BaseOAuthLoginSerializer):
    provider = "github"

    def get_user_info(self, access_token: str) -> dict:
        url = 'https://api.github.com/user'
        headers = {'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            email = data.get('email')
            if not email:
                email_response = requests.get('https://api.github.com/user/emails', headers=headers, timeout=10)
                email_response.raise_for_status()
                emails = email_response.json()
                primary_email = next((e for e in emails if e.get('primary') and e.get('verified')), None)
                email = primary_email.get('email') if primary_email else None

            return {
                'email': email,
                'name': data.get('name') or data.get('login'),
                'id': str(data.get('id')),
            }
        except requests.exceptions.RequestException as exc:
            raise serializers.ValidationError(f"OAuth provider error: {str(exc)}")
        except ValueError:
            raise serializers.ValidationError({"detail": "Invalid response from GitHub."})


class FacebookLoginSerializer(BaseOAuthLoginSerializer):
    provider = "facebook"

    def get_user_info(self, access_token: str) -> dict:
        # FIX (security): the access token was interpolated directly into the
        # URL string. Use `params=` so `requests` handles proper URL-encoding
        # and the token doesn't leak special characters into a malformed URL
        # or get logged unencoded by intermediate proxies that log full URLs.
        url = 'https://graph.facebook.com/me'
        params = {'fields': 'id,name,email', 'access_token': access_token}

        try:
            response = requests.get(url, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            return {
                'email': data.get('email'),
                'name': data.get('name'),
                'id': data.get('id'),
            }
        except requests.exceptions.RequestException as exc:
            raise serializers.ValidationError(f"OAuth provider error: {str(exc)}")
        except ValueError:
            raise serializers.ValidationError({"detail": "Invalid response from Facebook."})


class LinkedInLoginSerializer(BaseOAuthLoginSerializer):
    provider = "linkedin"

    def get_user_info(self, access_token: str) -> dict:
        url = "https://api.linkedin.com/v2/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            return {
                'email': data.get('email'),
                'name': data.get('name'),
                'id': data.get('sub'),
            }
        except requests.exceptions.RequestException as exc:
            raise serializers.ValidationError(f"OAuth provider error: {str(exc)}")
        except ValueError:
            raise serializers.ValidationError({"detail": "Invalid response from LinkedIn."})


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate_refresh(self, value: str) -> str:
        try:
            RefreshToken(value)
        except TokenError:
            raise serializers.ValidationError("Invalid refresh token.")
        return value

    def save(self) -> None:
        try:
            RefreshToken(self.validated_data["refresh"]).blacklist()
        except TokenError:
            pass


class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs: dict) -> dict:
        try:
            RefreshToken(attrs["refresh"])
        except TokenError:
            raise serializers.ValidationError({"refresh": "Invalid refresh token."})
        return attrs


class UserDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserDevice
        fields = ("id", "device_id", "device_name", "browser", "operating_system", "trusted", "last_login")
        read_only_fields = fields


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserProfile
        fields = ("phone_number", "avatar", "country", "timezone", "language")
        extra_kwargs = {
            "phone_number": {"required": False},
            "avatar": {"required": False, "allow_null": True},
            "country": {"required": False},
            "timezone": {"required": False},
            "language": {"required": False},
        }

    def validate_avatar(self, value: UploadedFile) -> UploadedFile:
        if not value:
            return value

        if value.size > 2 * 1024 * 1024:
            raise serializers.ValidationError("Avatar size must not exceed 2 MB.")

        allowed_types = {"image/jpeg", "image/png", "image/webp"}
        if getattr(value, 'content_type', None) not in allowed_types:
            raise serializers.ValidationError("Only JPEG, PNG, and WEBP images are allowed.")

        return value


class SocialAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = SocialAccount
        fields = ("id", "provider", "provider_email", "avatar_url", "created_at")
        read_only_fields = fields


# NOTE (dedup): TwoFactorVerifySerializer / TwoFactorLoginSerializer used to be
# defined HERE *and* again in sub_views/two_factor.py with slightly different
# validation (the two_factor.py versions add digit/length checks). That's a
# real duplicate-code bug — whichever one gets imported wins, silently, and
# nobody editing one would know the other exists. They belong to the 2FA
# feature, so the canonical versions now live only in sub_views/two_factor.py.
# Removed from this file to avoid drift between two divergent copies.