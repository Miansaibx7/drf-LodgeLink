from rest_framework import serializers
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

from django.core.validators import RegexValidator
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
import requests

User = get_user_model()

class RegisterSerializer(serializers.ModelSerializer):

    email = serializers.EmailField(required=True)
    # Removed `validators=[validate_password]` from here. It is now handled in `validate()` 
    # to allow attribute similarity checks against the email.
    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)
    confirm_password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)

    class Meta:
        model= User
        fields = ('email','password','confirm_password')

# validate email uniqueness and password confirmation
    def validate_email(self, value)-> str:
        value = value.lower().strip()
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email already exists.")
        return value

# validate password confirmation
    def validate(self, attrs)-> str:
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')
        if password != confirm_password:
            raise serializers.ValidationError({"confirm_password": "Password fields didn't match."})
        # Validate password here, passing a dummy user object so Django can check 
        # if the password is too similar to the user's email address.
        user_instance = User(email=attrs.get('email'))
        try:
            validate_password(password, user=user_instance)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"password": list(e.messages)})

        return attrs

# create user and set is_active and is_verified to False  
    def create(self, validated_data)-> str:
        validated_data.pop("confirm_password")
        user = User.objects.create_user(**validated_data,
        is_active = False,  # Set the user as inactive until email verification
        is_verified = False # Set the user as unverified until email verification
        )
        return user

    
    

class LoginSerializer(serializers.Serializer):

    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)

    def validate(self, attrs)-> str:
        email = attrs.get('email')
        password = attrs.get('password')
        #  Django's default `authenticate()` immediately returns None if `is_active=False`.
        # We must check the user's database status before calling authenticate() to give 
        # accurate error messages about verification.
        try:
            user_obj = User.objects.get(email=email.lower().strip())
            if not user_obj.is_active:
                raise serializers.ValidationError("Account is inactive. Please verify your email.")
            if not user_obj.is_verified:
                raise serializers.ValidationError("Email not verified. Please check your inbox for the OTP.")
        except User.DoesNotExist:
            pass  # Let authenticate() handle the generic failure below to prevent user enumeration

        user = authenticate(request=self.context.get('request'), email=email, password=password)
        if not user:
            raise serializers.ValidationError({"detail": "Invalid email or password."})

        attrs['user'] = user
        return attrs   


class BaseOTPSendSerializer(serializers.Serializer):

    email = serializers.EmailField(required=True)

    def validate_email(self, value)-> str:
        value = value.lower().strip()
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No account found with this email.")
        return value

class EmailOTPSendSerializer(BaseOTPSendSerializer):
    pass

class EmailOTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(max_length=6,min_length=6,required=True,
        validators=[RegexValidator(r'^\d{6}$', 'OTP must be exactly 6 digits.')])
    
    
class ResendEmailOTPSerializer(BaseOTPSendSerializer):
    pass

class PasswordResetOTPSendSerializer(BaseOTPSendSerializer):
    pass   


       
class PasswordResetOTPVerifySerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(max_length=6, min_length=6,required=True,
        validators=[RegexValidator(r'^\d{6}$', 'OTP must be exactly 6 digits.')]
    )
    # Moved validate_password to the validate() method below
    new_password = serializers.CharField(write_only=True,required=True,trim_whitespace=False)
    confirm_password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)

    def validate(self, attrs):
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')
        if new_password != confirm_password:
            raise serializers.ValidationError({"new_password": "Passwords don't match."}) 
        # Proper password validation for password resets
        user_instance = User(email=attrs.get('email'))
        try:
            validate_password(new_password, user=user_instance)
        except DjangoValidationError as e:
            raise serializers.ValidationError({"new_password": list(e.messages)})
        return attrs    
    


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, trim_whitespace=False)
    # Moved validate_password to the validate() method below
    new_password = serializers.CharField(write_only=True,trim_whitespace=False)
    confirm_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def validate_old_password(self, value):
        request = self.context.get("request")
        if request is None:
            raise serializers.ValidationError("Request context is required.")
        user = request.user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value

    def validate(self, attrs):
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

    def save(self):
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

    def validate(self, attrs):
        access_token = attrs.get('access_token')
        user_info = self.get_user_info(access_token)

        if not user_info:
            raise serializers.ValidationError({"detail": "Invalid or expired access token."})

        email = user_info.get("email")
        if not email:
            raise serializers.ValidationError({"detail": "Email not provided by provider."})
            
        email = email.lower().strip()
        full_name = user_info.get("name", "").strip()
        first_name = ""
        last_name = ""

        if full_name:
            parts = full_name.split(maxsplit=1)
            first_name = parts[0]
            last_name = parts[1] if len(parts) > 1 else ""

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
                
            # Individual checks are the best approach. 
            # It ensures we only write to the database if the status was actually False.
            if not user.is_active:
                user.is_active = True
                update_fields.append("is_active")

            if not user.is_verified:
                user.is_verified = True
                update_fields.append("is_verified")

            # Call save() exactly ONCE for the existing user
            if update_fields:
                user.save(update_fields=update_fields)

        except User.DoesNotExist:
            # FIX: Use first_name and last_name instead of the undefined 'name' variable
            user = User(
                email=email,
                first_name=first_name,
                last_name=last_name,
                is_active=True,
                is_verified=True
            )
            user.set_unusable_password()
            user.save()
            
        attrs['user'] = user
        return attrs

    def get_user_info(self, access_token):
        """Override in subclass to fetch user info from specific provider."""
        raise NotImplementedError("Subclasses must implement get_user_info()")




class GoogleLoginSerializer(BaseOAuthLoginSerializer):

    def get_user_info(self, access_token):
        url = 'https://www.googleapis.com/oauth2/v2/userinfo'
        headers = {'Authorization': f'Bearer {access_token}'}

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            return {'email': data.get('email'),'name': data.get('name'),}
        
        except requests.exceptions.RequestException as exc:
           raise serializers.ValidationError(f"OAuth provider error: {str(exc)}")
        


class GitHubLoginSerializer(BaseOAuthLoginSerializer):

    def get_user_info(self, access_token):
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
                primary_email = next((e for e in emails if e.get('primary')), emails[0] if emails else None)
                email = primary_email.get('email') if primary_email else None

            return {'email': email,'name': data.get('name') or data.get('login'),}
        
        except requests.exceptions.RequestException as exc:
           raise serializers.ValidationError(f"OAuth provider error: {str(exc)}")



class FacebookLoginSerializer(BaseOAuthLoginSerializer):

    def get_user_info(self, access_token):
        url = f'https://graph.facebook.com/me?fields=id,name,email&access_token={access_token}'

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            return {'email': data.get('email'),'name': data.get('name'),}
        
        except requests.exceptions.RequestException as exc:
           raise serializers.ValidationError(f"OAuth provider error: {str(exc)}")



class LinkedInLoginSerializer(BaseOAuthLoginSerializer):

    def get_user_info(self, access_token):
        url = "https://api.linkedin.com/v2/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}

        try:
            response = requests.get(url,headers=headers,timeout=10)
            response.raise_for_status()
            data = response.json()

            return {"email": data.get("email"),"name": data.get("name"),}

        except requests.exceptions.RequestException as exc:
           raise serializers.ValidationError(f"OAuth provider error: {str(exc)}")



class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def save(self):
        token = RefreshToken(self.validated_data["refresh"])
        token.blacklist()



class RefreshTokenSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate_refresh(self, value):

        try:
            token = RefreshToken(value)
        except (TokenError, InvalidToken):
            raise serializers.ValidationError("Invalid refresh token.")
        return value
