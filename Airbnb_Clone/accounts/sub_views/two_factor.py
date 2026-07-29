""" Two-Factor Authentication (2FA) endpoints. Uses TOTP (pyotp). """
import logging
from django.utils import timezone
import pyotp

from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework import status, serializers
from rest_framework.request import Request
from rest_framework.throttling import AnonRateThrottle
from django.db import transaction

from ..otp_logic.utils import get_tokens_for_user, extract_request_data
from ..otp_logic.services import handle_successful_login
from ..models import TwoFactorAuth, User
from ..exceptions import ServiceLayerError

logger = logging.getLogger(__name__)



# ===================== Throttles =====================
class TwoFactorLoginThrottle(AnonRateThrottle):
    """ Prevents brute-force attacks on unauthenticated 2FA verification.Uses the 'login_requests' rate configured in Django settings. """
    scope = 'login_requests'


# ====================================== Serializers ==================================================================
class TwoFactorEnableSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)

    def validate_password(self, value: str) -> str:
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Incorrect password.")
        return value


class TwoFactorVerifySerializer(serializers.Serializer):
    otp_code = serializers.CharField(max_length=6, min_length=6, required=True)

    def validate_otp_code(self, value: str) -> str:
        if not value.isdigit():
            raise serializers.ValidationError("OTP must be numeric.")
        return value


class TwoFactorDisableSerializer(TwoFactorEnableSerializer):
    pass

class TwoFactorBackupCodesSerializer(TwoFactorEnableSerializer):
    pass


class TwoFactorLoginChallengeSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    totp_code = serializers.CharField(max_length=6, min_length=6, required=True)

    def validate_email(self, value: str) -> str:
        return value.lower().strip()

    def validate_totp_code(self, value: str) -> str:
        # Accepts either a 6-digit TOTP code or a 6-character backup code
        if len(value) != 6:
            raise serializers.ValidationError("Code must be 6 characters.")
        return value


# ====================================== Service Layer ==================================================================
class TwoFactorService:
    @staticmethod
    def generate_secret() -> str:
        """Generate a cryptographically secure 6-digit OTP."""
        return pyotp.random_base32()

    @staticmethod
    def get_provisioning_uri(user: User, secret: str) -> str:
        return pyotp.totp.TOTP(secret).provisioning_uri(name=user.email,issuer_name="Airbnb_Clone")

    @staticmethod
    def verify_totp(secret: str, otp_code: str) -> bool:
        if not secret:
            return False
        totp = pyotp.TOTP(secret)
        return totp.verify(otp_code, valid_window=1)
    
    @staticmethod
    @transaction.atomic
    def enable_2fa(user: User, password: str) -> dict:
        if not user.check_password(password):
            raise ServiceLayerError("Incorrect password.")

        tfa, _ = TwoFactorAuth.objects.get_or_create(user=user)
        secret = TwoFactorService.generate_secret()

        tfa.secret_key = secret
        tfa.enabled = False
        tfa.backup_code_hashes = []
        tfa.save(update_fields=['secret_key', 'enabled', 'backup_code_hashes'])

        return {'secret': secret, 'provisioning_uri': TwoFactorService.get_provisioning_uri(user, secret)}
    
    @staticmethod
    @transaction.atomic
    def verify_and_enable_2fa(user: User, otp_code: str) -> dict:
        tfa = TwoFactorAuth.objects.select_for_update().get(user=user)

        if tfa.enabled:
            raise ServiceLayerError("2FA is already enabled.")

        if not TwoFactorService.verify_totp(tfa.secret_key, otp_code):
            raise ServiceLayerError("Invalid OTP code.")

        tfa.enabled = True
        tfa.enabled_at = timezone.now()
        backup_codes = [pyotp.random_base32()[:6] for _ in range(10)]
        tfa.set_backup_codes(backup_codes)

        tfa.save(update_fields=['enabled', 'enabled_at'])
        return {'backup_codes': backup_codes}

    @staticmethod
    @transaction.atomic
    def disable_2fa(user: User, password: str) -> None:
        if not user.check_password(password):
            raise ServiceLayerError("Incorrect password.")

        tfa = TwoFactorAuth.objects.select_for_update().filter(user=user, enabled=True).first()
        if not tfa:
            raise ServiceLayerError("2FA is not enabled.")

        tfa.disable()
        logger.info("2FA disabled for user %s", user.email)

    @staticmethod
    @transaction.atomic
    def generate_new_backup_codes(user: User, password: str) -> list:
        if not user.check_password(password):
            raise ServiceLayerError("Incorrect password.")

        tfa = TwoFactorAuth.objects.select_for_update().filter(user=user, enabled=True).first()
        if not tfa:
            raise ServiceLayerError("2FA is not enabled.")

        backup_codes = [pyotp.random_base32()[:6] for _ in range(10)]
        tfa.set_backup_codes(backup_codes)
        return backup_codes

    @staticmethod
    @transaction.atomic
    def verify_2fa_for_login(email: str, totp_code: str) -> User:
        user = User.objects.filter(email__iexact=email).first()
        if not user:
            # return the same generic error as an invalid code so this endpoint doesn't confirm account
            raise ServiceLayerError("Invalid credentials.")

        tfa = TwoFactorAuth.objects.select_for_update().filter(user=user).first()
        if not tfa or not tfa.enabled:
            return user  # 2FA not required for this account

        if TwoFactorService.verify_totp(tfa.secret_key, totp_code):
            tfa.last_used_at = timezone.now()
            tfa.save(update_fields=['last_used_at'])
            return user

        if tfa.consume_backup_code(totp_code):
            return user
        raise ServiceLayerError("Invalid 2FA code.")



# ====================================== Views ==================================================================
class TwoFactorSetupView(APIView):
    """ Step 1: Generate 2FA secret and provisioning URI. Requires password re-entry. """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorEnableSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        data = TwoFactorService.enable_2fa(user=request.user,password=serializer.validated_data['password'])

        return Response({'success': True,'message': '2FA setup initiated. Scan the QR code or enter the secret manually.',
            'data': data}, status=status.HTTP_200_OK)


class TwoFactorVerifyView(APIView):
    """  Verify OTP and enable 2FA. Returns backup codes for the user to store. """
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
        return Response({'success': True, 'message': '2FA disabled successfully.'}, status=status.HTTP_200_OK)


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
    2FA challenge, called after LoginView responds with requires_2fa=True.
    """
    # FIX (clarity): an empty list already behaves as "no permission checks",
    # which happens to equal AllowAny, but it's implicit and easy to misread
    # as "inherit the global IsAuthenticated default". Made explicit.
    permission_classes = [AllowAny]
    # FIX (security gap, see TwoFactorLoginThrottle above): this endpoint was
    # unthrottled. It's the only remaining path to complete a login for a
    # 2FA-protected account, and it accepts a 6-digit/6-character code — it
    # must be rate-limited independently of authentication.
    throttle_classes = [TwoFactorLoginThrottle]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorLoginChallengeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        totp_code = serializer.validated_data['totp_code']

        # Local import to avoid a circular import between views.py and
        # otp_logic.services (services.py does not import from sub_views).
        from ..otp_logic.services import handle_successful_login
        from ..views import _extract_request_data
        from django.contrib.auth.models import update_last_login

        user = TwoFactorService.verify_2fa_for_login(email, totp_code)

        request_data = _extract_request_data(request)
        tokens = get_tokens_for_user(user)
        handle_successful_login(user, request_data, tokens['jti'])
        update_last_login(None, user)

        logger.info("2FA login verified for %s", user.email)

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