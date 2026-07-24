"""Two-Factor Authentication (2FA) endpoints. Uses TOTP (pyotp)."""

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
# NOTE: these are the ONE canonical copy. serializers.py used to define
# TwoFactorVerifySerializer / TwoFactorLoginSerializer a second time with
# weaker validation (no digit check) — that duplicate has been removed from
# serializers.py to eliminate the drift/ambiguity.


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

    def validate_totp_code(self, value: str) -> str:
        # Backup codes are alphanumeric, so we only enforce length here, not
        # isdigit(), to allow either a TOTP code or a backup code.
        if len(value) != 6:
            raise serializers.ValidationError("Code must be 6 characters.")
        return value


# ===================== Service Layer =====================

class TwoFactorService:
    @staticmethod
    def generate_secret() -> str:
        return pyotp.random_base32()

    @staticmethod
    def get_provisioning_uri(user: User, secret: str) -> str:
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.email,
            issuer_name="Airbnb_Clone"
        )

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

        return {
            'secret': secret,
            'provisioning_uri': TwoFactorService.get_provisioning_uri(user, secret),
        }

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

        # FIX (bug): the original code did
        #   TwoFactorAuth.objects.filter(...).update(enabled=False, secret_key=None, backup_code_hashes=[])
        # but the model's `secret_key` field was `CharField` with NO
        # `null=True` — writing NULL into a NOT NULL column raises a raw
        # django.db.utils.IntegrityError at the DB level, which is not an
        # APIException and would surface as an unhandled 500. models.py now
        # declares `secret_key = models.CharField(..., null=True, blank=True)`
        # so this is safe. We also switch from a bare queryset `.update()`
        # (which bypasses model methods/signals) to the model instance's own
        # `disable()` method for consistency with the rest of the codebase,
        # and lock the row first to avoid racing a concurrent enable/verify.
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


# ===================== Views =====================

class TwoFactorSetupView(APIView):
    """Step 1: Generate 2FA secret and provisioning URI. Requires password re-entry."""
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
    """Step 2: Verify OTP and enable 2FA. Returns backup codes for the user to store."""
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

    FIX (missing wiring): this view existed before but nothing in LoginView
    ever redirected a 2FA-enabled user here — LoginView issued full tokens
    straight from email+password, making 2FA a no-op in practice. LoginView
    now withholds tokens and returns requires_2fa=True instead, so this view
    is the only path to a token pair for those accounts.

    NOTE: also fixed — this view previously issued tokens without ever
    creating a UserSession/UserDevice/AuditLog entry the way LoginView and
    BaseOAuthLoginView do, so 2FA logins were invisible to your session
    list and audit trail. It now calls the same handle_successful_login()
    used everywhere else.
    """
    permission_classes = []  # AllowAny by omission; auth is via email+code, not a session

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