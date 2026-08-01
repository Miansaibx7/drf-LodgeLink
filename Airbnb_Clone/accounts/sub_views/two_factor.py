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
        return Response({'success': True, 'message': '2FA verified.', 'tokens': tokens,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.get_full_name() or user.email
            }
        }, status=status.HTTP_200_OK)


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
    """Business logic layer managing Two-Factor Authentication secrets,
    verification, and backup codes. Views in this file are intentionally
    thin -- all real logic, locking, and audit logging lives here."""

    # FIX (entropy, external review): 6 characters from this 32-character
    # alphabet gives only 32^6 ~= 1.07 billion combinations -- thin for a
    # STATIC credential that never expires until used (unlike a TOTP
    # code, which rotates every 30 seconds). 10 characters gives
    # 32^10 ~= 1.15 quintillion, matching industry norms (Google, GitHub).
    # Account-level throttling already makes brute-forcing impractical
    # either way, but this is cheap insurance with no real UX cost.
    BACKUP_CODE_LENGTH = 10
    BACKUP_CODE_COUNT = 10

    # Precomputed once at class-body evaluation time (i.e. once per
    # process, not once per request) so that the "email doesn't exist"
    # branch in verify_2fa_for_login() can perform a real password-hash
    # comparison against SOMETHING, equalizing its response time against
    # the "email exists but password is wrong" branch. Without this, an
    # attacker could distinguish "no such account" from "wrong password"
    # purely by how long the response takes, which leaks account
    # existence -- exactly the kind of side channel authenticate_user()
    # already guards against on the primary login path.
    DUMMY_PASSWORD_HASH = make_password("dummy_password_for_timing_protection")

    @staticmethod
    def _generate_backup_codes() -> list[str]:
        """Generate a fresh batch of one-time backup codes.

        Uses a restricted alphabet excluding visually ambiguous
        characters (0/O, 1/I) since these codes are meant to be manually
        typed by a user from a printed/saved copy -- misreading a
        lookalike character is a common real-world failure mode for
        backup-code logins. Length and count MUST stay in sync with
        TwoFactorLoginChallengeSerializer.auth_code (exactly 6
        characters) -- that field validates any code, TOTP or backup, at
        that fixed length."""
        alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
        return [''.join(secrets.choice(alphabet) for _ in range(TwoFactorService.BACKUP_CODE_LENGTH))
                for _ in range(TwoFactorService.BACKUP_CODE_COUNT)]

    # Keys that must never end up in AuditLog.metadata even if a caller
    # accidentally passes them through **extra one day.
    _SENSITIVE_METADATA_KEYS = frozenset({"password", "old_password", "new_password", "confirm_password", "otp_code", "auth_code"})

    @staticmethod
    def _sanitize_metadata(metadata: dict) -> dict:
        """FIX (defense-in-depth, external review): extract_request_data()
        in otp_logic/utils.py already only ever whitelists specific
        non-sensitive keys (ip_address, user_agent, device_name, browser,
        operating_system, location, device_id) out of request.data -- it
        does NOT pass through raw request.data, so passwords do not
        currently reach AuditLog.metadata via that path. This helper is a
        cheap additional safeguard: if this method or any future caller
        ever accidentally includes a sensitive key in the **extra kwargs
        passed to _log_failure, it gets stripped here before the write,
        rather than relying solely on every future caller remembering not
        to pass it."""
        return {k: v for k, v in metadata.items() if k not in TwoFactorService._SENSITIVE_METADATA_KEYS}

    @staticmethod
    def _log_failure(user: User | None, action: str, request_data: dict, reason: str, **extra) -> None:
        """Centralized failure-path audit logging. Every ServiceLayerError
        raised anywhere in this class should be preceded by a call to
        this helper (with the one exception of the top-level
        "email doesn't exist" branch in verify_2fa_for_login, which calls
        it directly with user=None). Keeping this in one place means the
        metadata shape ({"status": "failed", "reason": ..., **extra}) can
        never drift between call sites the way it did before this helper
        existed.

        FIX (audit continuity, external review): wrapped the actual
        _log_audit() call in its own try/except. If AuditLog.objects.create()
        itself raises (e.g. a DB connectivity blip, deadlock, or the audit
        table specifically being unavailable), that failure is logged via
        the application logger and swallowed here -- it must NEVER mask
        or replace the real ServiceLayerError the caller is about to
        raise. Losing one audit-log row to a transient DB hiccup is
        acceptable; losing the actual security-relevant exception to a
        logging failure is not."""
        metadata = TwoFactorService._sanitize_metadata({"status": "failed", "reason": reason, **extra})
        try:
            _log_audit(user, action, request_data, metadata)
        except Exception:
            logger.exception("Failed to write AuditLog entry for failed 2FA action: %s", action)

    @staticmethod
    def _verify_password(user: User, password: str) -> None:
        """Raise ServiceLayerError if the given password doesn't match the user's stored password hash.
        Centralizing this in one helper method rather than repeating. """
        if not user.check_password(password):
            raise ServiceLayerError("Incorrect password.")

    @staticmethod
    def _get_locked_tfa(user: User, require_enabled: bool) -> TwoFactorAuth:
        """ Fetch a user's TwoFactorAuth row under select_for_update() and 
        validate its enabled/disabled state in one place."""
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
        """Generate a new base32-encoded TOTP secret key. This is the
        long-lived secret seeded into the user's authenticator app (via
        the provisioning URI / QR code) -- NOT a one-time code itself.
        The app uses this secret plus the current time to derive a fresh
        6-digit TOTP code every ~30 seconds."""
        return pyotp.random_base32()

    @staticmethod
    def get_provisioning_uri(user: User, secret: str) -> str:
        """Build the otpauth:// URI used to render the QR code the user
        scans into their authenticator app during setup."""
        return pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="Airbnb_Clone")

    @staticmethod
    def verify_totp(secret: str, otp_code: str) -> bool:
        """Check a submitted code against the current TOTP time window.
        valid_window=1 tolerates minor clock drift between server and
        authenticator app (accepts the previous, current, and next
        30-second window)."""
        if not secret:
            return False
        return pyotp.TOTP(secret).verify(otp_code, valid_window=1)

    @staticmethod
    def enable_2fa(user: User, password: str, request_data: dict) -> dict:
        """Step 1 of setup: verify the password, generate a fresh TOTP
        secret, and return the provisioning URI for the QR code.

        2FA is NOT active yet after this call -- `enabled` is explicitly
        set False here. verify_and_enable_2fa() below must separately
        confirm the user can produce a valid code from this secret before
        2FA actually turns on. This two-step design prevents a user from
        locking themselves out by enabling 2FA with a secret their
        authenticator app never actually received (e.g. a failed QR scan).

        Every call to this endpoint generates and persists a brand-new
        secret, overwriting any previous one -- that's a security-relevant
        event on its own, so it's logged to AuditLog regardless of
        whether 2FA ends up actually being enabled afterward."""
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
            # FIX (audit continuity, external review): the ServiceLayerError
            # branch above only catches EXPECTED business-logic failures.
            # An unexpected DB-level error (OperationalError, IntegrityError,
            # a deadlock, the DB going away mid-transaction) would skip it
            # entirely and leave no AuditLog trace of the failed attempt.
            # This still records a failure entry before re-raising the
            # original exception unchanged -- it does not swallow or mask it.
            TwoFactorService._log_failure(user, AuditLog.Action.TWO_FA_ENABLED, request_data, f"Unexpected error: {exc.__class__.__name__}")
            raise

        _log_audit(user, AuditLog.Action.TWO_FA_ENABLED, request_data, {"status": "setup_initiated"})
        return {
            'secret': secret,
            'provisioning_uri': TwoFactorService.get_provisioning_uri(user, secret)
        }

    @staticmethod
    def verify_and_enable_2fa(user: User, otp_code: str, request_data: dict) -> dict:
        """Step 2 of setup: confirm the user can produce a valid code
        from the secret issued in enable_2fa(), then flip 2FA on and
        issue a fresh set of backup codes.

        The lock (via _get_locked_tfa) is taken as the FIRST operation
        inside this method's transaction.atomic() block, before any of
        the enabled/expired checks run. This means the entire
        check-then-write sequence is one atomic unit: two near-simultaneous
        calls can no longer both pass the "not yet enabled" check and then
        each overwrite the other's freshly-generated backup codes -- the
        second call blocks until the first commits, then correctly sees
        enabled=True and cleanly rejects with "already enabled" instead.

        Audit logging on the failure path happens via try/except AFTER
        the atomic block exits (not inside it), so a rolled-back
        transaction never also discards the record of why it failed."""
        try:
            with transaction.atomic():
                tfa = TwoFactorService._get_locked_tfa(user, require_enabled=False)

                if not TwoFactorService.verify_totp(tfa.secret_key, otp_code):
                    raise ServiceLayerError("Invalid OTP code.")

                tfa.enabled = True
                tfa.enabled_at = timezone.now()
                backup_codes = TwoFactorService._generate_backup_codes()
                # set_backup_codes() persists backup_code_hashes itself
                # (see models.py) -- it does not need to be repeated in
                # this save's update_fields below.
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
        """Turn off 2FA for the user. Requires password re-entry since
        disabling 2FA is a security-downgrading action. Logs a
        TWO_FA_DISABLED AuditLog entry on both success and failure."""
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
        """Invalidate all existing backup codes and issue a fresh set.
        Requires password re-entry, since this rotates a security
        credential. Logged under its own dedicated BACKUP_CODES_REGENERATED
        action -- NOT under TWO_FA_ENABLED or TWO_FA_DISABLED, which this
        operation is neither of. (Requires AuditLog.Action to define
        BACKUP_CODES_REGENERATED in models.py.)"""
        try:
            TwoFactorService._verify_password(user, password)
            with transaction.atomic():
                tfa = TwoFactorService._get_locked_tfa(user, require_enabled=True)
                backup_codes = TwoFactorService._generate_backup_codes()
                # set_backup_codes() persists backup_code_hashes itself --
                # no separate .save() call needed here.
                tfa.set_backup_codes(backup_codes)
        except ServiceLayerError as exc:
            TwoFactorService._log_failure(
                user, AuditLog.Action.BACKUP_CODES_REGENERATED, request_data, str(exc),
                context="backup_code_regeneration"
            )
            raise
        except Exception as exc:
            # See enable_2fa() for why this broader net exists.
            TwoFactorService._log_failure(
                user, AuditLog.Action.BACKUP_CODES_REGENERATED, request_data,
                f"Unexpected error: {exc.__class__.__name__}", context="backup_code_regeneration"
            )
            raise

        _log_audit(user, AuditLog.Action.BACKUP_CODES_REGENERATED, request_data,
                   {"status": "backup_codes_regenerated"})
        return backup_codes

    @staticmethod
    def verify_2fa_for_login(email: str, password: str, auth_code: str, request_data: dict) -> User:
        """Verify BOTH factors for login completion: the account
        password AND a TOTP/backup code. This is the ONLY place that
        should ever issue tokens for a 2FA-protected account -- both
        factors are checked independently here, and every failure path
        (nonexistent email, wrong password, 2FA not enabled, wrong code)
        raises the SAME generic "Invalid credentials." / "Invalid 2FA
        code." message, so this endpoint never confirms account
        existence or 2FA status to an unauthenticated caller.

        Handles two categories of race condition:
        1. TOCTOU on the TwoFactorAuth row itself: select_for_update()
           is used with .filter(...).first() (not .get()) so that if the
           row is deleted between the initial unlocked read and the
           locked re-read (e.g. a concurrent disable_2fa() call), this
           raises a clean, audited ServiceLayerError instead of a raw
           DoesNotExist.
        2. Timing side-channel on account existence: the "email doesn't
           exist" branch performs a real check_password() call against a
           precomputed dummy hash, so its response time is equalized
           against the "email exists, password wrong" branch below it.
        """
        user = User.objects.filter(email__iexact=email).first()

        if not user:
            # Perform real hashing work here so this branch's timing
            # matches the "user exists but password is wrong" branch
            # below -- otherwise an attacker could distinguish
            # "no such account" from "wrong password" purely by response
            # time, which leaks account existence.
            check_password(password, TwoFactorService.DUMMY_PASSWORD_HASH)
            TwoFactorService._log_failure(None, AuditLog.Action.LOGIN, request_data, "Invalid credentials", email=email)
            raise ServiceLayerError("Invalid credentials.")

        try:
            TwoFactorService._verify_password(user, password)
            tfa = TwoFactorAuth.objects.filter(user=user).first()
            if not tfa or not tfa.enabled:
                # Password may have been correct, but this account has no
                # 2FA configured. This branch shouldn't be reachable in
                # normal flow (LoginView only ever returns
                # requires_2fa=True when tfa.enabled is True), so treat
                # it the same as any other invalid request rather than
                # silently completing login here.
                raise ServiceLayerError("Invalid credentials.")
        except ServiceLayerError as exc:
            TwoFactorService._log_failure(user, AuditLog.Action.LOGIN, request_data, str(exc))
            # FIX (account enumeration, external review -- confirmed real):
            # _verify_password() raises ServiceLayerError("Incorrect
            # password.") specifically, which is a DIFFERENT string than
            # the "Invalid credentials." raised for a nonexistent email
            # above. A bare `raise` here would let "Incorrect password."
            # propagate straight to the client, letting an attacker
            # distinguish "valid email, wrong password" from "no such
            # account" just by reading the response body -- completely
            # defeating the DUMMY_PASSWORD_HASH timing-equalization work
            # above, which only protects against a TIMING side-channel,
            # not a TEXT side-channel. Every failure in this method must
            # surface the exact same message regardless of which check
            # actually failed.
            raise ServiceLayerError("Invalid credentials.")

        # Sanitize incidental whitespace a user might paste in around a
        # copied code, without changing the code's actual characters.
        auth_code_clean = auth_code.strip()

        # --- Path 1: standard TOTP code (always purely numeric, 6 digits) ---
        # FIX (TOCTOU race, external review -- confirmed real): TOTP
        # verification previously ran against the UNLOCKED `tfa.secret_key`
        # fetched earlier, before the atomic block even opened. If a
        # concurrent enable_2fa()/verify_and_enable_2fa() call rotated the
        # secret in the window between that unlocked read and the locked
        # re-read below, the code would have been validated against a
        # secret that might already be stale by the time the lock was
        # acquired -- yet last_used_at would still be saved as if the
        # validation were current. The check now runs entirely INSIDE the
        # atomic block, against tfa_locked.secret_key (the definitively
        # current value under the row lock), not the earlier unlocked copy.
        if auth_code_clean.isdigit() and len(auth_code_clean) == 6:
            with transaction.atomic():
                # .filter().first() instead of .get() -- handles the edge
                # case where the row was deleted (e.g. a concurrent
                # disable_2fa()) between the unlocked read above and this
                # locked re-read, without raising a raw DoesNotExist.
                tfa_locked = TwoFactorAuth.objects.select_for_update().filter(id=tfa.id).first()
                if not tfa_locked:
                    TwoFactorService._log_failure(
                        user, AuditLog.Action.LOGIN, request_data,
                        "2FA configuration modified mid-request (TOTP path)"
                    )
                    raise ServiceLayerError("2FA configuration was modified. Please try again.")

                if TwoFactorService.verify_totp(tfa_locked.secret_key, auth_code_clean):
                    tfa_locked.last_used_at = timezone.now()
                    tfa_locked.save(update_fields=['last_used_at'])
                    _log_audit(user, AuditLog.Action.LOGIN, request_data, {"status": "success", "method": "TOTP"})
                    return user
                # Falls through to the backup-code path below if the code
                # doesn't verify -- a 6-digit numeric string could in
                # principle also collide with a backup code's format, so
                # we don't short-circuit on a failed TOTP check alone.

        # --- Path 2: backup code. Normalized to uppercase since
        # _generate_backup_codes() only ever produces uppercase
        # characters -- without this, a user typing their saved code in
        # lowercase would always fail the hash comparison. ---
        auth_code_upper = auth_code_clean.upper()
        with transaction.atomic():
            tfa_locked = TwoFactorAuth.objects.select_for_update().filter(id=tfa.id).first()
            if not tfa_locked:
                TwoFactorService._log_failure(
                    user, AuditLog.Action.LOGIN, request_data,
                    "2FA configuration modified mid-request (backup code path)"
                )
                raise ServiceLayerError("2FA configuration was modified. Please try again.")

            if tfa_locked.consume_backup_code(auth_code_upper):
                _log_audit(user, AuditLog.Action.LOGIN, request_data, {"status": "success", "method": "Backup Code"})
                return user

        # Neither a valid TOTP code nor a valid backup code.
        TwoFactorService._log_failure(user, AuditLog.Action.LOGIN, request_data, "Invalid TOTP or Backup code")
        raise ServiceLayerError("Invalid 2FA code.")


# ====================================== Views ==================================================================
# FIX (architectural regression, removed): a previous draft of this file
# introduced a Base2FAView with its own handle_exception() override that
# translated ServiceLayerError into a Response directly, bypassing
# custom_global_exception_handler entirely. That created TWO places in
# the codebase that decide how a ServiceLayerError becomes an HTTP
# response, and they disagreed: the override's response omitted the
# "errors" key present on every other endpoint's error responses, and it
# skipped the logger.warning(...) call that custom_global_exception_handler
# performs for every handled client error, creating a blind spot in
# application logs specifically for 2FA errors. ServiceLayerError already
# flows correctly through custom_global_exception_handler for every other
# view in this codebase -- there is no reason these views need special
# handling. All views below are plain APIView; no exception override.

class TwoFactorSetupView(APIView):
    """Step 1: Generate 2FA secret and provisioning URI for QR-code
    display. Requires password re-entry."""
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
    """Step 2: Verify a live TOTP code to confirm setup and actually
    enable 2FA. Returns backup codes for the user to store securely --
    these are shown exactly once and cannot be retrieved again later
    (only regenerated, which invalidates the old set)."""
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
    """Disable 2FA for the authenticated user. Requires password
    re-entry, since this downgrades account security."""
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
    """Generate a fresh set of backup codes, invalidating all previous
    ones. Requires password re-entry, since this rotates a security
    credential."""
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
        return Response({
            'success': True,
            'message': 'New backup codes generated.',
            'backup_codes': codes
        }, status=status.HTTP_200_OK)


class TwoFactorLoginView(APIView):
    """2FA login challenge -- called after LoginView responds with
    requires_2fa=True for an email+password pair belonging to a
    2FA-enabled account. This is the ONLY endpoint that issues tokens
    for such an account; it independently re-verifies both the password
    AND a TOTP/backup code before doing so.

    Unauthenticated by design (permission_classes=[AllowAny]) since no
    session exists yet at this point in the login flow -- protected
    instead by dual-layer throttling: a volumetric per-IP limit and a
    targeted per-account limit, so neither a single attacking IP nor a
    distributed attack against one victim account can bypass rate
    limiting by working around just one dimension of it."""
    permission_classes = [AllowAny]
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

        # .get('jti') rather than tokens['jti'] -- defends against a
        # KeyError if the jti claim is ever absent from the token dict,
        # matching the same defensive pattern already used in
        # LogoutView elsewhere in this codebase.
        handle_successful_login(user, request_data, tokens.get('jti'))
        # FIX (external review): Django's default update_last_login
        # receiver ignores `sender` entirely, so passing None "worked" --
        # but the documented signature is update_last_login(sender, user,
        # **kwargs), where sender is conventionally the model class. If
        # any custom signal receiver is ever connected that DOES inspect
        # sender, passing None instead of the real model class would
        # silently break it. Passing user.__class__ costs nothing and
        # matches the documented contract.
        update_last_login(user.__class__, user)

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