""" Two-Factor Authentication (2FA) endpoints. Uses TOTP (pyotp).
Provides:
- TOTP secret generation and QR-code provisioning
- Two-step enable flow (generate secret -> confirm with a live code)
- Backup codes (one-time-use, human-typeable, case-insensitive on input)
- Disable / regenerate-backup-codes flows (all require password re-entry)
- Login-time 2FA challenge (requires BOTH password and a TOTP/backup code). """

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
from django.contrib.auth.hashers import check_password, make_password

from ..otp_logic.utils import get_tokens_for_user, extract_request_data
from ..otp_logic.services import _log_audit, handle_successful_login

from ..models import TwoFactorAuth, User, AuditLog
from ..exceptions import ServiceLayerError

logger = logging.getLogger(__name__)


# ===================== Throttles =====================================================================================
class TwoFactorIPThrottle(AnonRateThrottle):
    """Prevents volumetric brute-force attacks from a single IP address
    hammering the unauthenticated 2FA login-challenge endpoint.

    REQUIRED SETTINGS: add 'login_ip_requests' to
    REST_FRAMEWORK['DEFAULT_THROTTLE_RATES'] in settings.py. If this key
    is missing, DRF silently disables throttling for this scope entirely
    (no error raised) -- this is the exact same failure mode that once
    left TwoFactorLoginView completely unthrottled earlier in this
    codebase's history, so it's called out explicitly here.
    """
    scope = 'login_ip_requests'


class TwoFactorAccountThrottle(SimpleRateThrottle):
    """Prevents a distributed/botnet attack that spreads requests across
    many IPs but targets one victim account, by keying the throttle on
    the submitted email instead of the client IP.

    REQUIRED SETTINGS: add 'login_account_requests' to
    REST_FRAMEWORK['DEFAULT_THROTTLE_RATES'] in settings.py -- same
    silent-disable risk as TwoFactorIPThrottle above if omitted.
    """
    scope = 'login_account_requests'

    def get_cache_key(self, request, view):
        """ Key the throttle bucket on the normalized (lowercased, stripped) submitted email rather than the client IP. """
        email = request.data.get('email', '')
        if not email:
            return None
        return self.cache_format % {'scope': self.scope, 'ident': email.lower().strip()}


# ====================================== Serializers ==================================================================
class TwoFactorPasswordSerializer(serializers.Serializer):
    """ Reusable input serializer for the three authenticated endpoints that only need the user's current password 
    re-entered as a confirmation step (setup, disable, regenerate-backup-codes). """
    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)


class TwoFactorVerifySerializer(serializers.Serializer):
    """ Input serializer for step 2 of setup: confirming the user's authenticator app is correctly configured by
    submitting a live 6-digit TOTP code. """
    otp_code = serializers.RegexField(regex=r'^\d{6}$', required=True,
                error_messages={'invalid': 'OTP must be exactly 6 digits.'})


class TwoFactorLoginChallengeSerializer(serializers.Serializer):
    """Input serializer for the login-time 2FA challenge. """
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True, required=True, trim_whitespace=False)
    auth_code = serializers.CharField(max_length=10, min_length=6, required=True)

    def validate_email(self, value: str) -> str:
        """Normalize email the same way every other email field. """
        return value.lower().strip()


# ====================================== Service Layer ==================================================================
class TwoFactorService:
    """ Business logic layer managing Two-Factor Authentication secrets, verification, and backup codes. 
    Views in this file are intentionally thin -- all real logic, locking, and audit logging lives here. """

    BACKUP_CODE_LENGTH = 10
    BACKUP_CODE_COUNT = 10
    # Generated at module load for accurate timing equalization (prevents user-enumeration timing attacks)
    DUMMY_PASSWORD_HASH = make_password("dummy_password_for_timing_protection")

    @staticmethod
    def _generate_backup_codes() -> list[str]:
        """ Generate a fresh batch of one-time backup codes. """
        alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        return [''.join(secrets.choice(alphabet) for _ in range(TwoFactorService.BACKUP_CODE_LENGTH))
                for _ in range(TwoFactorService.BACKUP_CODE_COUNT)]

    # Keys that must never end up in AuditLog.metadata even if a caller
    # accidentally passes them through **extra one day.
    _SENSITIVE_METADATA_KEYS = frozenset({"password", "old_password", "new_password", "confirm_password", "otp_code", "auth_code"})

    @staticmethod
    def _sanitize_metadata(metadata: dict) -> dict:
        """ Remove any sensitive keys from the metadata dict before logging to AuditLog. """
        return {k: v for k, v in metadata.items() if k not in TwoFactorService._SENSITIVE_METADATA_KEYS}

    @staticmethod
    def _log_failure(user: User | None, action: str, request_data: dict, reason: str, **extra) -> None:
        """ Centralized failure audit logging. """
        metadata = TwoFactorService._sanitize_metadata({"status": "failed", "reason": reason, **extra})
        try:
            _log_audit(user, action, request_data, metadata)
        except Exception:
            logger.exception("Failed to write AuditLog entry for failed 2FA action: %s", action)

    @staticmethod
    def _verify_password(user: User, password: str) -> None:
        """ Raise ServiceLayerError if the given password doesn't match the user's stored password hash.
        Centralizing this in one helper method rather than repeating. """
        if not user.check_password(password):
            raise ServiceLayerError("Incorrect password.")

    @staticmethod
    def _get_locked_tfa(user: User, require_enabled: bool) -> TwoFactorAuth:
        """ Fetch a user's TwoFactorAuth row under select_for_update() and validate its enabled/disabled state in one place."""
        tfa = TwoFactorAuth.objects.select_for_update().filter(user=user).first()
        if not tfa:
            raise ServiceLayerError("2FA is not enabled." if require_enabled else "2FA setup not initiated. Please request a new secret.")
        if require_enabled and not tfa.enabled:
            raise ServiceLayerError("2FA is not enabled.")
        if not require_enabled and tfa.enabled:
            raise ServiceLayerError("2FA is already enabled.")
        return tfa

    @staticmethod
    def generate_secret() -> str:
        """ Generate a new base32-encoded TOTP secret key. """
        return pyotp.random_base32()

    @staticmethod
    def get_provisioning_uri(user: User, secret: str) -> str:
        """ Build the URI used to render the QR code the user scans into their authenticator app during setup."""
        return pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="Airbnb_Clone")

    @staticmethod
    def verify_totp(secret: str, otp_code: str) -> bool:
        """ Verify a TOTP code against the given secret, allowing a 1-step window for clock skew. """
        if not secret:
            return False
        return pyotp.TOTP(secret).verify(otp_code, valid_window=1)

    @staticmethod
    def enable_2fa(user: User, password: str, request_data: dict) -> dict:
        """ Verify the password, generate a fresh TOTP secret, and return the provisioning URI for the QR code. """
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
        except Exception as exc:
            TwoFactorService._log_failure(user, AuditLog.Action.TWO_FA_ENABLED, request_data, f"Unexpected error: {exc.__class__.__name__}")
            raise

        _log_audit(user, AuditLog.Action.TWO_FA_ENABLED, request_data, {"status": "setup_initiated"})
        return {'secret': secret,'provisioning_uri': TwoFactorService.get_provisioning_uri(user, secret)}

    @staticmethod
    def verify_and_enable_2fa(user: User, otp_code: str, request_data: dict) -> dict:
        """ Verify a live TOTP code and, if valid, enable 2FA for the user and return backup codes. """
        try:
            with transaction.atomic():
                tfa = TwoFactorService._get_locked_tfa(user, require_enabled=False)

                if not TwoFactorService.verify_totp(tfa.secret_key, otp_code):
                    raise ServiceLayerError("Invalid OTP code.")

                tfa.enabled = True
                tfa.enabled_at = timezone.now()
                backup_codes = TwoFactorService._generate_backup_codes()
                # set_backup_codes() persists backup_code_hashes itself (see models.py).So does not need to be repeated it.
                tfa.set_backup_codes(backup_codes)
                tfa.save(update_fields=['enabled', 'enabled_at'])
        except ServiceLayerError as exc:
            TwoFactorService._log_failure(user, AuditLog.Action.TWO_FA_ENABLED, request_data, str(exc))
            raise
        except Exception as exc:
            # See enable_2fa() for why this broader net exists.
            TwoFactorService._log_failure(user, AuditLog.Action.TWO_FA_ENABLED, request_data, f"Unexpected error: {exc.__class__.__name__}")
            raise

        _log_audit(user, AuditLog.Action.TWO_FA_ENABLED, request_data, {"status": "success"})
        return {'backup_codes': backup_codes}

    @staticmethod
    def disable_2fa(user: User, password: str, request_data: dict) -> None:
        """ Turn off 2FA for the user. Requires password re-entry since disabling 2FA is a security-downgrading action.
        Logs a TWO_FA_DISABLED AuditLog entry on both success and failure."""
        try:
            TwoFactorService._verify_password(user, password)
            with transaction.atomic():
                tfa = TwoFactorService._get_locked_tfa(user, require_enabled=True)
                tfa.disable()
        except ServiceLayerError as exc:
            TwoFactorService._log_failure(user, AuditLog.Action.TWO_FA_DISABLED, request_data, str(exc))
            raise
        except Exception as exc:
            # See enable_2fa() for why this broader net exists.
            TwoFactorService._log_failure(user, AuditLog.Action.TWO_FA_DISABLED, request_data, f"Unexpected error: {exc.__class__.__name__}")
            raise

        logger.info("2FA disabled for user %s", user.email)
        _log_audit(user, AuditLog.Action.TWO_FA_DISABLED, request_data, {"status": "success"})

    @staticmethod
    def generate_new_backup_codes(user: User, password: str, request_data: dict) -> list[str]:
        """ Invalidate all existing backup codes and issue a fresh set. Requires password re-entry, since this rotates
        a security credential. """
        try:
            TwoFactorService._verify_password(user, password)
            with transaction.atomic():
                tfa = TwoFactorService._get_locked_tfa(user, require_enabled=True)
                backup_codes = TwoFactorService._generate_backup_codes()
                # set_backup_codes() persists backup_code_hashes itself no separate .save() call needed here.
                tfa.set_backup_codes(backup_codes)
        except ServiceLayerError as exc:
            TwoFactorService._log_failure(user, AuditLog.Action.BACKUP_CODES_REGENERATED, request_data, str(exc),
                context="backup_code_regeneration")
            raise
        except Exception as exc:
            # See enable_2fa() for why this broader net exists.
            TwoFactorService._log_failure(user, AuditLog.Action.BACKUP_CODES_REGENERATED, request_data,
                f"Unexpected error: {exc.__class__.__name__}", context="backup_code_regeneration")
            raise

        _log_audit(user, AuditLog.Action.BACKUP_CODES_REGENERATED, request_data,{"status": "backup_codes_regenerated"})
        return backup_codes

    @staticmethod
    def verify_2fa_for_login(email: str, password: str, auth_code: str, request_data: dict) -> User:
        """ Verify both the password and a TOTP/backup code for a 2FA-enabled account. 
        Returns the User on success, raises. ServiceLayerError on failure. """
        user = User.objects.filter(email__iexact=email).first()

        if not user:
            # Perform real hashing work here so this branch's timing matches the "user exists but password is wrong" branch
            # below otherwise an attacker could distinguish "no such account" from "wrong password" purely by response time.
            check_password(password, TwoFactorService.DUMMY_PASSWORD_HASH)
            TwoFactorService._log_failure(None, AuditLog.Action.LOGIN, request_data, "Invalid credentials", email=email)
            raise ServiceLayerError("Invalid credentials.")

        try:
            TwoFactorService._verify_password(user, password)
            tfa = TwoFactorAuth.objects.filter(user=user).first()
            if not tfa or not tfa.enabled:
                # Password may have been correct, but this account has no 2FA configured.This branch shouldn't be reachable in
                # normal flow (LoginView only ever returns requires_2fa=True when tfa.enabled is True), so treat
                # it the same as any other invalid request rather than silently completing login here.
                raise ServiceLayerError("Invalid credentials.")
        except ServiceLayerError as exc:
            TwoFactorService._log_failure(user, AuditLog.Action.LOGIN, request_data, str(exc))
            raise ServiceLayerError("Invalid credentials.")

        # Sanitize incidental whitespace a user might paste in around a copied code, without changing the code's actual characters.
        auth_code_clean = auth_code.strip()

        if auth_code_clean.isdigit() and len(auth_code_clean) == 6:
            with transaction.atomic():
                # .filter().first() instead of .get() -- handles the edge
                tfa_locked = TwoFactorAuth.objects.select_for_update().filter(id=tfa.id).first()
                if not tfa_locked:
                    TwoFactorService._log_failure(user, AuditLog.Action.LOGIN, request_data,"2FA configuration modified mid-request (TOTP path)")
                    raise ServiceLayerError("2FA configuration was modified. Please try again.")

                if TwoFactorService.verify_totp(tfa_locked.secret_key, auth_code_clean):
                    tfa_locked.last_used_at = timezone.now()
                    tfa_locked.save(update_fields=['last_used_at'])
                    _log_audit(user, AuditLog.Action.LOGIN, request_data, {"status": "success", "method": "TOTP"})
                    return user
                

        # backup code. Normalized to uppercase since _generate_backup_codes() only ever produces uppercase characters 
        # without this, a user typing their saved code in lowercase would always fail the hash comparison.
        auth_code_upper = auth_code_clean.upper()
        with transaction.atomic():
            tfa_locked = TwoFactorAuth.objects.select_for_update().filter(id=tfa.id).first()
            if not tfa_locked:
                TwoFactorService._log_failure(user, AuditLog.Action.LOGIN, request_data,"2FA configuration modified mid-request (backup code path)")
                raise ServiceLayerError("2FA configuration was modified. Please try again.")

            if tfa_locked.consume_backup_code(auth_code_upper):
                _log_audit(user, AuditLog.Action.LOGIN, request_data, {"status": "success", "method": "Backup Code"})
                return user

        # Neither a valid TOTP code nor a valid backup code.
        TwoFactorService._log_failure(user, AuditLog.Action.LOGIN, request_data, "Invalid TOTP or Backup code")
        raise ServiceLayerError("Invalid 2FA code.")


# ====================================== Views ==================================================================
class TwoFactorSetupView(APIView):
    """ Generate 2FA secret and provisioning URI for QR-code display. Requires password re-entry."""
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorPasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        request_data = extract_request_data(request)

        data = TwoFactorService.enable_2fa(user=request.user,password=serializer.validated_data['password'],
            request_data=request_data)
        
        return Response({'success': True,'message': '2FA setup initiated. Scan the QR code or enter the secret manually.',
            'data': data}, status=status.HTTP_200_OK)


class TwoFactorVerifyView(APIView):
    """ Verify a live TOTP code to confirm setup and actually enable 2FA. Returns backup codes for the user to store securely. """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorVerifySerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        request_data = extract_request_data(request)

        result = TwoFactorService.verify_and_enable_2fa(user=request.user,otp_code=serializer.validated_data['otp_code'],
            request_data=request_data)
        
        return Response({'success': True,'message': '2FA enabled successfully. Please store your backup codes securely.',
            'backup_codes': result['backup_codes']}, status=status.HTTP_200_OK)


class TwoFactorDisableView(APIView):
    """ Disable 2FA for the authenticated user. Requires password re-entry, since this downgrades account security. """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorPasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        request_data = extract_request_data(request)

        TwoFactorService.disable_2fa(user=request.user,password=serializer.validated_data['password'],
            request_data=request_data)
        
        return Response({'success': True, 'message': '2FA disabled successfully.'}, status=status.HTTP_200_OK)


class TwoFactorBackupCodesView(APIView):
    """ Generate a fresh set of backup codes, invalidating all previous ones. Requires password re-entry, 
    since this rotates a security credential. """
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorPasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        request_data = extract_request_data(request)

        codes = TwoFactorService.generate_new_backup_codes(user=request.user,password=serializer.validated_data['password'],
            request_data=request_data)
        
        return Response({'success': True,'message': 'New backup codes generated.','backup_codes': codes},status=status.HTTP_200_OK)


class TwoFactorLoginView(APIView):
    """ Handle the login-time 2FA challenge. Requires both the user's password and a valid TOTP or backup code. """
    permission_classes = [AllowAny]
    throttle_classes = [TwoFactorIPThrottle, TwoFactorAccountThrottle]

    def post(self, request: Request) -> Response:
        serializer = TwoFactorLoginChallengeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        auth_code = serializer.validated_data['auth_code']
        request_data = extract_request_data(request)

        user = TwoFactorService.verify_2fa_for_login(email=email,password=password,auth_code=auth_code,request_data=request_data)
        tokens = get_tokens_for_user(user)

        handle_successful_login(user, request_data, tokens.get('jti'))
        update_last_login(user.__class__, user)

        logger.info("2FA login verified for %s", user.email)
        return Response({'success': True,'message': '2FA verified.','tokens': tokens,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.get_full_name() or user.email
            }
        }, status=status.HTTP_200_OK)