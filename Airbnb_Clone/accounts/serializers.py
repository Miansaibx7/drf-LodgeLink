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
        fields = ('email','password','confirm_password')

# validate email uniqueness and password confirmation
    def validate_email(self, value: str) -> str:
        """Ensure email is unique and normalized."""
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
        
        attrs['email'] = email
        return attrs 
    


class ChangePasswordSerializer(serializers.Serializer):
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

    access_token = serializers.CharField(required=True)
    # Subclasses must set this to the provider name (e.g., 'google')
    provider = None

    def _split_name(self, full_name: str) -> tuple[str, str]:
        # Added safeguard against empty or whitespace-only names returned by external providers
        full_name = full_name.strip()
        if not full_name:
            return "", ""
        parts = full_name.split(maxsplit=1)
        return parts[0], parts[1] if len(parts) > 1 else ""

    def validate(self, attrs: dict) -> dict:
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

        # UPGRADE: Entire user/social account handling block wrapped in a database-level transaction context
        with transaction.atomic():
            try:
                user = User.objects.get(email=email)
                update_fields = []

                # Update first_name if it was missing
                if not user.first_name and first_name:
                    user.first_name = first_name
                    update_fields.append("first_name")

                # Update last_name if it was missing    
                if not user.last_name and last_name:
                    user.last_name = last_name
                    update_fields.append("last_name")

                # It ensures we only write to the database if the status was actually False.    
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

            # --- Create or update SocialAccount ---    
            social_account, created = SocialAccount.objects.get_or_create(user=user,
                provider=self.provider,defaults={'provider_user_id': provider_user_id, 'provider_email': email}
            )
            # Update if provider_user_id changed (unlikely)
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

            # Enforce validation to eliminate account takeover vulnerabilities
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
        if not value:
            return value

        # Max 2 MB
        if value.size > 2 * 1024 * 1024:
            raise serializers.ValidationError("Avatar size must not exceed 2 MB.")

        allowed_types = {"image/jpeg","image/png","image/webp",}

        if getattr(value, 'content_type', None) not in allowed_types:
            raise serializers.ValidationError({"avatar": "Only JPEG, PNG, and WEBP images are allowed."})
        
        return value
        