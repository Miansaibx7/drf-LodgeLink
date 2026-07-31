""" Two-Factor Authentication (2FA) endpoints. Uses TOTP (pyotp).
Provides robust protections against brute-force attacks, timing attacks, and race conditions. """
import logging
import pyotp
import secrets

from rest_framework.views import APIView
from rest_framework import status, serializers
from rest_framework.response import Response
from rest_framework.request import Request

from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.throttling import AnonRateThrottle, SimpleRateThrottle

from django.utils import timezone
from django.db import transaction
from django.contrib.auth.models import update_last_login
from django.contrib.auth.hashers import check_password,make_password

from ..otp_logic.utils import get_tokens_for_user, extract_request_data
from ..otp_logic.services import _log_audit, handle_successful_login

from ..models import TwoFactorAuth, User, AuditLog
from ..exceptions import ServiceLayerError

logger = logging.getLogger(__name__)


# ===================== Throttles =====================================================================================
class TwoFactorIPThrottle(AnonRateThrottle):
    """ Prevents volumetric brute force attacks from a single IP address. """
    scope = 'login_ip_requests'

class TwoFactorAccountThrottle(SimpleRateThrottle):
    """ Prevents distributed botnet attacks by throttling attempts against a specific email. """
    scope = 'login_account_requests'

    def get_cache_key(self, request, view):
        email = request.data.get('email', '')
        if not email:
            return None  # Missing email will be caught by the serializer
        return self.cache_format % {'scope': self.scope,'ident': email.lower().strip()}


    
# ====================================== Serializers ==================================================================
class TwoFactorPasswordSerializer(serializers.Serializer):
    """ Reusable serializer for endpoints that require password confirmation. """
    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)


class TwoFactorVerifySerializer(serializers.Serializer):
    otp_code = serializers.CharField(max_length=6, min_length=6, required=True)

    def validate_otp_code(self, value: str) -> str:
        if not value.isdigit():
            raise serializers.ValidationError("OTP must be numeric.")
        return value


class TwoFactorLoginChallengeSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)
    auth_code = serializers.CharField(max_length=12, min_length=6, required=True)

    def validate_email(self, value: str) -> str:
        return value.lower().strip()



# ====================================== Service Layer ==================================================================
class TwoFactorService:
    """ Business logic layer managing Two-Factor Authentication secrets, verification, and backup codes. """

    BACKUP_CODE_LENGTH = 6
    BACKUP_CODE_COUNT = 10
    
    # Generated at module load for accurate timing equalization (prevents user-enumeration timing attacks)
    DUMMY_PASSWORD_HASH = make_password("dummy_password_for_timing_protection")

    @staticmethod
    def _generate_backup_codes() -> list[str]:
        # Excludes visually ambiguous characters: 0, 1, I, O
        alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        return [''.join(secrets.choice(alphabet) for _ in range(TwoFactorService.BACKUP_CODE_LENGTH))
                for _ in range(TwoFactorService.BACKUP_CODE_COUNT)]

    @staticmethod
    def _log_failure(user: User | None, action: str, request_data: dict, reason: str, **extra) -> None:
        """ Centralized failure audit logging. """
        metadata = {"status": "failed", "reason": reason}
        metadata.update(extra)
        _log_audit(user, action, request_data, metadata)

    @staticmethod
    def _verify_password(user: User, password: str) -> None:
        """ DRY helper for password verification. """
        if not user.check_password(password):
            raise ServiceLayerError("Incorrect password.")

    @staticmethod
    def _get_locked_tfa(user: User, require_enabled: bool) -> TwoFactorAuth:
        """ Fetches the 2FA row, locks it for update to prevent race conditions, and validates state. """
        tfa = TwoFactorAuth.objects.select_for_update().filter(user=user).first()
        if not tfa:
            raise ServiceLayerError(
                "2FA is not enabled." if require_enabled else "2FA setup not initiated. Please request a new secret."
            )
        if require_enabled and not tfa.enabled:
            raise ServiceLayerError("2FA is not enabled.")
        if not require_enabled and tfa.enabled:
            raise ServiceLayerError("2FA is already enabled.")
        return tfa

    @staticmethod
    def generate_secret() -> str:
        return pyotp.random_base32()

    @staticmethod
    def get_provisioning_uri(user: User, secret: str) -> str:
        return pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="Airbnb_Clone")

    @staticmethod
    def verify_totp(secret: str, otp_code: str) -> bool:
        if not secret:
            return False
        return pyotp.TOTP(secret).verify(otp_code, valid_window=1)

    @staticmethod
    def enable_2fa(user: User, password: str, request_data: dict) -> dict:
        try:
            TwoFactorService._verify_password(user, password)
            with transaction.atomic():
                tfa, _ = TwoFactorAuth.objects.get_or_create(user=user)
                secret = TwoFactorService.generate_secret()
                tfa.secret_key = secret
                tfa.enabled = False
                tfa.backup_code_hashes = []
                tfa.save(update_fields=['secret_key', 'enabled', 'backup_code_hashes'])
        except ServiceLayerError as exc:
            TwoFactorService._log_failure(user, AuditLog.Action.TWO_FA_ENABLED, request_data, str(exc))
            raise

        _log_audit(user, AuditLog.Action.TWO_FA_ENABLED, request_data, {"status": "setup_initiated"})
        return {
            'secret': secret, 
            'provisioning_uri': TwoFactorService.get_provisioning_uri(user, secret)
        }

    @staticmethod
    def verify_and_enable_2fa(user: User, otp_code: str, request_data: dict) -> dict:
        try:
            with transaction.atomic():
                tfa = TwoFactorService._get_locked_tfa(user, require_enabled=False)

                if not TwoFactorService.verify_totp(tfa.secret_key, otp_code):
                    raise ServiceLayerError("Invalid OTP code.")

                tfa.enabled = True
                tfa.enabled_at = timezone.now()
                backup_codes = TwoFactorService._generate_backup_codes()
                tfa.set_backup_codes(backup_codes)
                tfa.save(update_fields=['enabled', 'enabled_at'])
        except ServiceLayerError as exc:
            TwoFactorService._log_failure(user, AuditLog.Action.TWO_FA_ENABLED, request_data, str(exc))
            raise

        _log_audit(user, AuditLog.Action.TWO_FA_ENABLED, request_data, {"status": "success"})
        return {'backup_codes': backup_codes}

    @staticmethod
    def disable_2fa(user: User, password: str, request_data: dict) -> None:
        try:
            TwoFactorService._verify_password(user, password)
            with transaction.atomic():
                tfa = TwoFactorService._get_locked_tfa(user, require_enabled=True)
                tfa.disable()
        except ServiceLayerError as exc:
            TwoFactorService._log_failure(user, AuditLog.Action.TWO_FA_DISABLED, request_data, str(exc))
            raise

        logger.info("2FA disabled for user %s", user.email)
        _log_audit(user, AuditLog.Action.TWO_FA_DISABLED, request_data, {"status": "success"})

    @staticmethod
    def generate_new_backup_codes(user: User, password: str, request_data: dict) -> list[str]:
        try:
            TwoFactorService._verify_password(user, password)
            with transaction.atomic():
                tfa = TwoFactorService._get_locked_tfa(user, require_enabled=True)
                backup_codes = TwoFactorService._generate_backup_codes()
                tfa.set_backup_codes(backup_codes)
        except ServiceLayerError as exc:
            TwoFactorService._log_failure(user, AuditLog.Action.BACKUP_CODES_REGENERATED, 
                request_data, str(exc), context="backup_code_regeneration")
            raise

        _log_audit(user, AuditLog.Action.BACKUP_CODES_REGENERATED, request_data, {"status": "backup_codes_regenerated"})
        return backup_codes

    @staticmethod
    def verify_2fa_for_login(email: str, password: str, auth_code: str, request_data: dict) -> User:
        """ 
        Verify BOTH factors for login completion: password AND a TOTP/backup code.
        Contains race-condition protections and timing-attack mitigation.
        """
        user = User.objects.filter(email__iexact=email).first()

        if not user:
            # Perform actual hashing work to equalize response times against user-enumeration
            check_password(password, TwoFactorService.DUMMY_PASSWORD_HASH)
            TwoFactorService._log_failure(None, AuditLog.Action.LOGIN, request_data, "Invalid credentials", email=email)
            raise ServiceLayerError("Invalid credentials.")

        try:
            TwoFactorService._verify_password(user, password)
            tfa = TwoFactorAuth.objects.filter(user=user).first()
            if not tfa or not tfa.enabled:
                raise ServiceLayerError("Invalid credentials.")
        except ServiceLayerError as exc:
            TwoFactorService._log_failure(user, AuditLog.Action.LOGIN, request_data, str(exc))
            raise

        # Sanitize whitespace
        auth_code_clean = auth_code.strip()

        # Check standard TOTP
        if auth_code_clean.isdigit() and TwoFactorService.verify_totp(tfa.secret_key, auth_code_clean):
            with transaction.atomic():
                # Safe locking: handles edge case where 2FA row is deleted mid-request
                tfa_locked = TwoFactorAuth.objects.select_for_update().filter(id=tfa.id).first()
                if not tfa_locked:
                    raise ServiceLayerError("2FA configuration was modified. Please try again.")
                
                tfa_locked.last_used_at = timezone.now()
                tfa_locked.save(update_fields=['last_used_at'])

            _log_audit(user, AuditLog.Action.LOGIN, request_data, {"status": "success", "method": "TOTP"})
            return user

        # Check Backup Codes (Normalized to uppercase for case-sensitive hashing)
        auth_code_upper = auth_code_clean.upper()
        with transaction.atomic():
            tfa_locked = TwoFactorAuth.objects.select_for_update().filter(id=tfa.id).first()
            if not tfa_locked:
                raise ServiceLayerError("2FA configuration was modified. Please try again.")

            if tfa_locked.consume_backup_code(auth_code_upper):
                _log_audit(user, AuditLog.Action.LOGIN, request_data, {"status": "success", "method": "Backup Code"})
                return user

        # Validation failure
        TwoFactorService._log_failure(user, AuditLog.Action.LOGIN, request_data, "Invalid TOTP or Backup code")
        raise ServiceLayerError("Invalid 2FA code.")


    

# ====================================== Views ===========================================================================
class TwoFactorSetupView(APIView):
    """ Generate 2FA secret and provisioning URI. Requires password re-entry. """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorPasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        request_data = extract_request_data(request)

        data = TwoFactorService.enable_2fa(
            user=request.user, 
            password=serializer.validated_data['password'],
            request_data=request_data
        )
        return Response({
            'success': True, 
            'message': '2FA setup initiated. Scan the QR code or enter the secret manually.', 
            'data': data
        }, status=status.HTTP_200_OK)


class TwoFactorVerifyView(APIView):
    """ Verify OTP and enable 2FA. Returns backup codes for the user to store. """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorVerifySerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        request_data = extract_request_data(request)

        result = TwoFactorService.verify_and_enable_2fa(
            user=request.user, 
            otp_code=serializer.validated_data['otp_code'],
            request_data=request_data
        )
        return Response({
            'success': True, 
            'message': '2FA enabled successfully. Please store your backup codes securely.', 
            'backup_codes': result['backup_codes']
        }, status=status.HTTP_200_OK)


class TwoFactorDisableView(APIView):
    """ Disable 2FA for the authenticated user (requires password). """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorPasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        request_data = extract_request_data(request)

        TwoFactorService.disable_2fa(
            user=request.user, 
            password=serializer.validated_data['password'], 
            request_data=request_data
        )
        return Response({'success': True, 'message': '2FA disabled successfully.'}, status=status.HTTP_200_OK)


class TwoFactorBackupCodesView(APIView):
    """ Generate new backup codes (invalidates old ones). """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorPasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        request_data = extract_request_data(request)

        codes = TwoFactorService.generate_new_backup_codes(
            user=request.user, 
            password=serializer.validated_data['password'], 
            request_data=request_data
        )
        return Response({'success': True, 'message': 'New backup codes generated.', 'backup_codes': codes},status=status.HTTP_200_OK)


class TwoFactorLoginView(APIView):
    """ 2FA challenge, called after LoginView responds with requires_2fa=True. """
    permission_classes = [AllowAny]
    # Employs dual-layer throttling against both volumetric IP and targeted account attacks
    throttle_classes = [TwoFactorIPThrottle, TwoFactorAccountThrottle]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorLoginChallengeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        auth_code = serializer.validated_data['auth_code']
        request_data = extract_request_data(request)

        user = TwoFactorService.verify_2fa_for_login(
            email=email, 
            password=password, 
            auth_code=auth_code,
            request_data=request_data
        )
        tokens = get_tokens_for_user(user)

        # Uses .get('jti') to safely extract the JWT ID without triggering a KeyError if absent
        handle_successful_login(user, request_data, tokens.get('jti'))
        update_last_login(None, user)

        logger.info("2FA login verified for %s", user.email)
        return Response({
            'success': True, 
            'message': '2FA verified.', 
            'tokens': tokens,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.get_full_name() or user.email
            }
        }, status=status.HTTP_200_OK)