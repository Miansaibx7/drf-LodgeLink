""" Two-Factor Authentication (2FA) endpoints. Uses TOTP (Time‑based One‑Time Password) with pyotp. """
import logging
from django.utils import timezone
import pyotp

from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status, serializers
from rest_framework.request import Request
from django.db import transaction

from ..otp_logic.utils import get_tokens_for_user
from ..models import TwoFactorAuth, User
from ..exceptions import ServiceLayerError

logger = logging.getLogger(__name__)


# ===================== Serializers =====================

class TwoFactorEnableSerializer(serializers.Serializer):
    """Serializer to enable 2FA – returns provisioning URI and secret."""
    
    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)

    def validate_password(self, value: str) -> str:
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Incorrect password.")
        return value



class TwoFactorVerifySerializer(serializers.Serializer):
    """Serializer to verify and activate 2FA after scanning QR code."""

    otp_code = serializers.CharField(max_length=6, min_length=6, required=True)

    def validate_otp_code(self, value: str) -> str:
        if not value.isdigit():
            raise serializers.ValidationError("OTP must be numeric.")
        return value


class TwoFactorDisableSerializer(serializers.Serializer):
    """Serializer to disable 2FA (requires password verification)."""

    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)

    def validate_password(self, value: str) -> str:
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Incorrect password.")
        return value


class TwoFactorBackupCodesSerializer(serializers.Serializer):
    """Serializer for generating new backup codes (password required)."""

    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)

    def validate_password(self, value: str) -> str:
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Incorrect password.")
        return value


class TwoFactorLoginChallengeSerializer(serializers.Serializer):
    """Serializer for 2FA challenge during login."""

    email = serializers.EmailField(required=True)
    totp_code = serializers.CharField(max_length=6, min_length=6, required=True)

    def validate_totp_code(self, value: str) -> str:
        if not value.isdigit():
            raise serializers.ValidationError("OTP must be numeric.")
        return value


# ===================== Service Layer =================================================

class TwoFactorService:
    """Business logic for Two-Factor Authentication."""

    @staticmethod
    def generate_secret() -> str:
        """Generate a new TOTP secret (Base32)."""
        return pyotp.random_base32()

    @staticmethod
    def get_provisioning_uri(user: User, secret: str) -> str:
        """Generate the provisioning URI for QR code generation."""
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name=getattr(user, 'get_full_name', lambda: user.email)() or user.email
        )

    @staticmethod
    def verify_totp(secret: str, otp_code: str) -> bool:
        """Verify a TOTP code against a secret."""
        totp = pyotp.TOTP(secret)
        return totp.verify(otp_code, valid_window=1)  # allow 1 step drift

    @staticmethod
    @transaction.atomic
    def enable_2fa(user: User, password: str) -> dict:
        """
        Step 1: Generate a new secret and return it (and provisioning URI) to the user.
        Does NOT enable 2FA yet – user must verify with a code first.
        """
        # Check password again (already validated in serializer, but double‑check)
        if not user.check_password(password):
            raise ServiceLayerError("Incorrect password.")

        # Get or create TwoFactorAuth record
        tfa, created = TwoFactorAuth.objects.get_or_create(user=user)

        # Generate a new secret
        secret = TwoFactorService.generate_secret()
        tfa.secret_key = secret
        tfa.enabled = False  # ensure not enabled yet
        tfa.backup_code_hashes = []  # reset backup codes
        tfa.save(update_fields=['secret_key', 'enabled', 'backup_code_hashes'])

        provisioning_uri = TwoFactorService.get_provisioning_uri(user, secret)

        return {
            'secret': secret,
            'provisioning_uri': provisioning_uri,
        }

    @staticmethod
    @transaction.atomic
    def verify_and_enable_2fa(user: User, otp_code: str) -> dict:
        """
        Step 2: Verify the TOTP code and enable 2FA for the user.
        Also generates backup codes.
        """
        tfa = TwoFactorAuth.objects.select_for_update().get(user=user)
        if tfa.enabled:
            raise ServiceLayerError("2FA is already enabled.")

        # Verify the code using the stored secret
        if not TwoFactorService.verify_totp(tfa.secret_key, otp_code):
            raise ServiceLayerError("Invalid OTP code.")

        # Enable 2FA
        tfa.enabled = True
        tfa.enabled_at = timezone.now()
        tfa.save(update_fields=['enabled', 'enabled_at'])

        # Generate backup codes (10 codes)
        backup_codes = [pyotp.random_base32()[:6] for _ in range(10)]
        tfa.set_backup_codes(backup_codes)

        # Log the event (optional)
        # (you can add AuditLog creation here if needed)

        return {
            'backup_codes': backup_codes,  # return raw codes for the user to store
        }

    @staticmethod
    @transaction.atomic
    def disable_2fa(user: User, password: str) -> None:
        """Disable 2FA for the user (requires password verification)."""
        if not user.check_password(password):
            raise ServiceLayerError("Incorrect password.")

        try:
            tfa = TwoFactorAuth.objects.get(user=user)
        except TwoFactorAuth.DoesNotExist:
            raise ServiceLayerError("2FA is not enabled.")

        tfa.disable()  # sets enabled=False and disabled_at
        logger.info("2FA disabled for user %s", user.email)

    @staticmethod
    @transaction.atomic
    def generate_new_backup_codes(user: User, password: str) -> list:
        """Generate new backup codes (invalidates old ones)."""
        if not user.check_password(password):
            raise ServiceLayerError("Incorrect password.")

        try:
            tfa = TwoFactorAuth.objects.get(user=user)
        except TwoFactorAuth.DoesNotExist:
            raise ServiceLayerError("2FA is not enabled.")

        if not tfa.enabled:
            raise ServiceLayerError("2FA is not enabled.")

        # Generate 10 new backup codes
        backup_codes = [pyotp.random_base32()[:6] for _ in range(10)]
        tfa.set_backup_codes(backup_codes)
        logger.info("New backup codes generated for user %s", user.email)
        return backup_codes

    @staticmethod
    @transaction.atomic
    def verify_2fa_for_login(email: str, totp_code: str) -> User:
        """
        Verify 2FA during login.
        This is called after primary authentication (email/password) succeeds.
        """
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise ServiceLayerError("Invalid credentials.")

        try:
            tfa = TwoFactorAuth.objects.get(user=user)
        except TwoFactorAuth.DoesNotExist:
            # 2FA not set up – allow login (or raise error depending on policy)
            # We'll raise an error if 2FA is required; but we can also let it pass.
            # For our implementation, we require 2FA only if enabled.
            # So if not enabled, we return user (login allowed).
            return user

        if not tfa.enabled:
            return user

        # Verify TOTP
        if TwoFactorService.verify_totp(tfa.secret_key, totp_code):
            # Optionally update last_used_at
            tfa.last_used_at = timezone.now()
            tfa.save(update_fields=['last_used_at'])
            return user
        else:
            # Try backup codes
            if tfa.consume_backup_code(totp_code):
                tfa.last_used_at = timezone.now()
                tfa.save(update_fields=['last_used_at'])
                return user
            else:
                raise ServiceLayerError("Invalid 2FA code.")


# ===================== Views =====================

class TwoFactorSetupView(APIView):
    """
    Step 1: Generate 2FA secret and provisioning URI.
    User must be authenticated and must verify their password.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorEnableSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        data = TwoFactorService.enable_2fa(
            user=request.user,
            password=serializer.validated_data['password']
        )
        return Response({
            'success': True,
            'message': '2FA setup initiated. Scan the QR code or enter the secret manually.',
            'data': data
        }, status=status.HTTP_200_OK)


class TwoFactorVerifyView(APIView):
    """
    Step 2: Verify OTP and enable 2FA.
    Returns backup codes for the user to store.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorVerifySerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        result = TwoFactorService.verify_and_enable_2fa(
            user=request.user,
            otp_code=serializer.validated_data['otp_code']
        )
        return Response({
            'success': True,
            'message': '2FA enabled successfully. Please store your backup codes securely.',
            'backup_codes': result['backup_codes']
        }, status=status.HTTP_200_OK)


class TwoFactorDisableView(APIView):
    """Disable 2FA for the authenticated user (requires password)."""
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorDisableSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        TwoFactorService.disable_2fa(
            user=request.user,
            password=serializer.validated_data['password']
        )
        return Response({
            'success': True,
            'message': '2FA disabled successfully.'
        }, status=status.HTTP_200_OK)


class TwoFactorBackupCodesView(APIView):
    """Generate new backup codes (invalidates old ones)."""
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorBackupCodesSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        codes = TwoFactorService.generate_new_backup_codes(
            user=request.user,
            password=serializer.validated_data['password']
        )
        return Response({
            'success': True,
            'message': 'New backup codes generated.',
            'backup_codes': codes
        }, status=status.HTTP_200_OK)


class TwoFactorLoginView(APIView):
    """
    Endpoint for 2FA challenge during login.
    This is called after primary authentication (email/password) succeeded.
    Expects email and TOTP/backup code.
    This view returns a JWT token if 2FA is verified.
    """
    permission_classes = []  # AllowAny, but we handle authentication manually

    def post(self, request: Request) -> Response:
        serializer = TwoFactorLoginChallengeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        totp_code = serializer.validated_data['totp_code']

        try:
            user = TwoFactorService.verify_2fa_for_login(email, totp_code)
        except ServiceLayerError as e:
            return Response({'success': False, 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Generate tokens
        tokens = get_tokens_for_user(user)

        # Log the login (you can also create session here)
        # For brevity, we just return tokens
        return Response({
            'success': True,
            'message': '2FA verified.',
            'tokens': tokens,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.get_full_name() or user.email,
            }
        }, status=status.HTTP_200_OK)