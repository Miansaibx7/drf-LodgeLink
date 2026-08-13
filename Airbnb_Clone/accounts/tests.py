"""Test suite for the `accounts` app.
Covers:
- User model / manager
- Registration (including the duplicate-email race path)
- Login (success, brute-force lockout, unverified/inactive accounts)
- Email verification OTP (send, verify, expiry, attempt-blocking)
- Password reset OTP
- Change password
- Two-Factor Authentication (setup, verify/enable, login challenge,
  disable, backup codes) — including the password-required-on-login
  security fix and the account-enumeration masking fix
- Account deletion requests (create, cancel, status)

Run with:
    python manage.py test accounts

Notes:
- Email sending is mocked throughout (`_send_email`) so tests never touch
  real SMTP and never depend on template files rendering correctly.
- Throttle scopes are overridden to very high limits for functional tests,
  except in the dedicated throttling test class.
"""

import pyotp
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.urls import reverse

from rest_framework.test import APITestCase
from rest_framework import status

from .models import (
    EmailOTP, UserProfile, UserSession, AuditLog,
    LoginAttempt, TwoFactorAuth, AccountDeletionRequest
)

User = get_user_model()

# Permissive throttle rates for functional tests – prevents rate‑limiting interference
PERMISSIVE_THROTTLES = {
    "otp_requests": "1000/min",
    "login_requests": "1000/min",
    "register_requests": "1000/min",
    "login_ip_requests": "1000/min",
    "login_account_requests": "1000/min",
    "user": "1000/min",
    "anon": "1000/min",
}


def make_user(email="user@example.com", password="StrongPassw0rd!99", **extra):
    """Helper: create an already-active, already-verified user."""
    defaults = {"is_active": True, "is_verified": True, "terms_accepted": True}
    defaults.update(extra)
    return User.objects.create_user(email=email, password=password, **defaults)


# ================================== Model / Manager Tests =================================
class UserModelTests(TestCase):
    def test_create_user_normalizes_and_lowercases_email(self):
        user = User.objects.create_user(email="  Test@Example.COM ", password="pw")
        self.assertEqual(user.email, "test@example.com")

    def test_create_user_without_email_raises(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(email="", password="pw")

    def test_create_user_defaults_inactive_and_unverified(self):
        user = User.objects.create_user(email="new@example.com", password="pw")
        self.assertFalse(user.is_active)
        self.assertFalse(user.is_verified)

    def test_create_user_without_password_is_unusable(self):
        user = User.objects.create_user(email="nopass@example.com", password=None)
        self.assertFalse(user.has_usable_password())

    def test_create_superuser_sets_all_flags(self):
        admin = User.objects.create_superuser(email="admin@example.com", password="pw")
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)
        self.assertTrue(admin.is_active)
        self.assertTrue(admin.is_verified)

    def test_create_superuser_rejects_is_staff_false(self):
        with self.assertRaises(ValueError):
            User.objects.create_superuser(email="admin2@example.com", password="pw", is_staff=False)

    def test_get_full_name_and_short_name(self):
        user = make_user(email="jane@example.com", first_name="Jane", last_name="Doe")
        self.assertEqual(user.get_full_name(), "Jane Doe")
        self.assertEqual(user.get_short_name(), "Jane")
        user2 = make_user(email="noname@example.com")
        self.assertEqual(user2.get_short_name(), "noname")


class BaseOTPModelTests(TestCase):
    def setUp(self):
        self.user = make_user()

    def test_set_otp_hashes_and_resets_state(self):
        otp = EmailOTP.objects.create(user=self.user)
        otp.set_otp("123456")
        self.assertNotEqual(otp.otp_hash, "123456")
        self.assertEqual(otp.attempts, 0)
        self.assertIsNone(otp.blocked_until)

    def test_verify_otp_success_deletes_row(self):
        otp = EmailOTP.objects.create(user=self.user)
        otp.set_otp("123456")
        self.assertTrue(otp.verify_otp("123456"))
        self.assertFalse(EmailOTP.all_objects.filter(pk=otp.pk).exists())

    def test_verify_otp_wrong_code_increments_attempts(self):
        otp = EmailOTP.objects.create(user=self.user)
        otp.set_otp("123456")
        self.assertFalse(otp.verify_otp("000000"))
        otp.refresh_from_db()
        self.assertEqual(otp.attempts, 1)

    def test_verify_otp_blocks_after_max_attempts(self):
        otp = EmailOTP.objects.create(user=self.user)
        otp.set_otp("123456")
        for _ in range(EmailOTP.MAX_ATTEMPTS):
            otp.verify_otp("000000")
        otp.refresh_from_db()
        self.assertTrue(otp.is_blocked)
        self.assertFalse(otp.verify_otp("123456"))

    def test_verify_otp_expired_fails(self):
        otp = EmailOTP.objects.create(user=self.user)
        otp.set_otp("123456")
        otp.created_at = timezone.now() - timedelta(minutes=EmailOTP.OTP_EXPIRY_MINUTES + 1)
        otp.save(update_fields=["created_at"])
        self.assertFalse(otp.verify_otp("123456"))

    def test_active_manager_excludes_expired(self):
        otp = EmailOTP.objects.create(user=self.user)
        otp.set_otp("123456")
        otp.created_at = timezone.now() - timedelta(minutes=EmailOTP.OTP_EXPIRY_MINUTES + 1)
        otp.save(update_fields=["created_at"])
        self.assertIsNone(EmailOTP.objects.get_active_for_user(self.user))
        self.assertTrue(EmailOTP.all_objects.filter(user=self.user).exists())


class LoginAttemptModelTests(TestCase):
    def test_increment_blocks_after_max_attempts(self):
        attempt = LoginAttempt.objects.create(email="x@example.com", ip_address="127.0.0.1")
        for _ in range(5):
            attempt.increment(minutes=15, max_attempts=5)
        attempt.refresh_from_db()
        self.assertTrue(attempt.is_blocked())


class TwoFactorAuthModelTests(TestCase):
    def setUp(self):
        self.user = make_user()
        self.tfa = TwoFactorAuth.objects.create(user=self.user)

    def test_enable_and_disable(self):
        self.tfa.enable("SECRETKEY")
        self.assertTrue(self.tfa.enabled)
        self.assertEqual(self.tfa.secret_key, "SECRETKEY")
        self.tfa.disable()
        self.assertFalse(self.tfa.enabled)
        self.assertIsNone(self.tfa.secret_key)
        self.assertEqual(self.tfa.backup_code_hashes, [])

    def test_consume_backup_code_success_and_single_use(self):
        self.tfa.set_backup_codes(["ABCD1234", "WXYZ9999"])
        self.assertTrue(self.tfa.consume_backup_code("ABCD1234"))
        self.assertFalse(self.tfa.consume_backup_code("ABCD1234"))
        self.assertTrue(self.tfa.consume_backup_code("WXYZ9999"))

    def test_consume_backup_code_invalid(self):
        self.tfa.set_backup_codes(["ABCD1234"])
        self.assertFalse(self.tfa.consume_backup_code("WRONGCODE"))


# ============================================================
# Registration Tests
# ============================================================
@override_settings(REST_FRAMEWORK={"DEFAULT_THROTTLE_RATES": PERMISSIVE_THROTTLES})
class RegistrationTests(APITestCase):
    def setUp(self):
        self.url = reverse('accounts:register')

    @patch("accounts.otp_logic.services.send_registration_otp", return_value=True)
    def test_register_success_creates_inactive_unverified_user(self, mock_send):
        payload = {
            "email": "newuser@example.com",
            "password": "StrongPassw0rd!99",
            "confirm_password": "StrongPassw0rd!99",
            "terms_accepted": True,
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

        user = User.objects.get(email="newuser@example.com")
        self.assertFalse(user.is_active)
        self.assertFalse(user.is_verified)
        self.assertTrue(UserProfile.objects.filter(user=user).exists())
        self.assertTrue(AuditLog.objects.filter(user=user, action="REGISTER").exists())

    def test_register_password_mismatch_rejected(self):
        payload = {
            "email": "mismatch@example.com",
            "password": "StrongPassw0rd!99",
            "confirm_password": "Different!99",
            "terms_accepted": True,
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_terms_not_accepted_rejected(self):
        payload = {
            "email": "noterms@example.com",
            "password": "StrongPassw0rd!99",
            "confirm_password": "StrongPassw0rd!99",
            "terms_accepted": False,
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_duplicate_email_rejected(self):
        make_user(email="dupe@example.com")
        payload = {
            "email": "dupe@example.com",
            "password": "StrongPassw0rd!99",
            "confirm_password": "StrongPassw0rd!99",
            "terms_accepted": True,
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch("accounts.otp_logic.services.send_registration_otp", return_value=False)
    def test_register_otp_send_failure_returns_clean_error_not_500(self, mock_send):
        payload = {
            "email": "otpfail@example.com",
            "password": "StrongPassw0rd!99",
            "confirm_password": "StrongPassw0rd!99",
            "terms_accepted": True,
        }
        response = self.client.post(self.url, payload, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


# ============================================================
# Login Tests
# ============================================================
@override_settings(REST_FRAMEWORK={"DEFAULT_THROTTLE_RATES": PERMISSIVE_THROTTLES})
class LoginTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.url = reverse('accounts:login')
        self.password = "StrongPassw0rd!99"
        self.user = make_user(email="login@example.com", password=self.password)

    def test_login_success_returns_tokens(self):
        response = self.client.post(self.url, {"email": self.user.email, "password": self.password}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("tokens", response.data)
        self.assertTrue(UserSession.objects.filter(user=self.user, is_active=True).exists())

    def test_login_wrong_password_rejected(self):
        response = self.client.post(self.url, {"email": self.user.email, "password": "wrong"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_nonexistent_email_gives_generic_error(self):
        response = self.client.post(self.url, {"email": "nobody@example.com", "password": "whatever"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("Invalid email or password", str(response.data))

    def test_login_inactive_account_rejected(self):
        user = make_user(email="inactive@example.com", password=self.password, is_active=False)
        response = self.client.post(self.url, {"email": user.email, "password": self.password}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_unverified_account_rejected(self):
        user = make_user(email="unverified@example.com", password=self.password, is_verified=False)
        response = self.client.post(self.url, {"email": user.email, "password": self.password}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_brute_force_lockout(self):
        for _ in range(5):
            self.client.post(self.url, {"email": self.user.email, "password": "wrong"}, format="json")
        attempt = LoginAttempt.objects.get(email=self.user.email)
        self.assertTrue(attempt.is_blocked())
        response = self.client.post(self.url, {"email": self.user.email, "password": self.password}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_success_resets_previous_failed_attempts(self):
        self.client.post(self.url, {"email": self.user.email, "password": "wrong"}, format="json")
        self.client.post(self.url, {"email": self.user.email, "password": self.password}, format="json")
        self.assertFalse(LoginAttempt.objects.filter(email=self.user.email).exists())

    def test_login_with_2fa_enabled_withholds_tokens(self):
        tfa = TwoFactorAuth.objects.create(user=self.user)
        tfa.enable(pyotp.random_base32())
        response = self.client.post(self.url, {"email": self.user.email, "password": self.password}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data.get("requires_2fa"))
        self.assertNotIn("tokens", response.data)


# ============================================================
# Email Verification OTP Tests
# ============================================================
@override_settings(REST_FRAMEWORK={"DEFAULT_THROTTLE_RATES": PERMISSIVE_THROTTLES})
class EmailOTPTests(APITestCase):
    def setUp(self):
        cache.clear()
        self.send_url = reverse('accounts:email_otp_send')
        self.verify_url = reverse('accounts:email_otp_verify')
        self.user = make_user(email="verify@example.com", is_active=False, is_verified=False)

    @patch("accounts.otp_logic.utils._send_email", return_value=True)
    def test_send_and_verify_otp_activates_user(self, mock_send):
        self.client.post(self.send_url, {"email": self.user.email}, format="json")
        otp_obj = EmailOTP.objects.get_active_for_user(self.user)
        self.assertIsNotNone(otp_obj)

    @patch("accounts.otp_logic.utils._send_email", return_value=True)
    @patch("accounts.otp_logic.services.generate_otp", return_value="123456")
    def test_verify_otp_with_correct_code_activates_user(self, mock_gen, mock_send):
        self.client.post(self.send_url, {"email": self.user.email}, format="json")
        response = self.client.post(self.verify_url, {"email": self.user.email, "code": "123456"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_active)
        self.assertTrue(self.user.is_verified)

    def test_verify_otp_invalid_format_rejected(self):
        response = self.client.post(self.verify_url, {"email": self.user.email, "code": "12"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_send_otp_unknown_email_rejected(self):
        response = self.client.post(self.send_url, {"email": "nobody@example.com"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


# ============================================================
# Password Reset Tests
# ============================================================
@override_settings(REST_FRAMEWORK={"DEFAULT_THROTTLE_RATES": PERMISSIVE_THROTTLES})
class PasswordResetTests(APITestCase):
    def setUp(self):
        self.send_url = reverse('accounts:password_reset_send')
        self.verify_url = reverse('accounts:password_reset_verify')
        self.old_password = "OldPassw0rd!99"
        self.user = make_user(email="reset@example.com", password=self.old_password)

    @patch("accounts.otp_logic.utils._send_email", return_value=True)
    @patch("accounts.otp_logic.services.generate_otp", return_value="654321")
    def test_reset_password_success(self, mock_gen, mock_send):
        self.client.post(self.send_url, {"email": self.user.email}, format="json")
        new_password = "BrandNewPassw0rd!99"
        response = self.client.post(self.verify_url, {
            "email": self.user.email,
            "code": "654321",
            "new_password": new_password,
            "confirm_password": new_password,
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))

    @patch("accounts.otp_logic.utils._send_email", return_value=True)
    @patch("accounts.otp_logic.services.generate_otp", return_value="654321")
    def test_reset_password_cannot_reuse_current_password(self, mock_gen, mock_send):
        self.client.post(self.send_url, {"email": self.user.email}, format="json")
        response = self.client.post(self.verify_url, {
            "email": self.user.email,
            "code": "654321",
            "new_password": self.old_password,
            "confirm_password": self.old_password,
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


# ============================================================
# Change Password (Authenticated)
# ============================================================
@override_settings(REST_FRAMEWORK={"DEFAULT_THROTTLE_RATES": PERMISSIVE_THROTTLES})
class ChangePasswordTests(APITestCase):
    def setUp(self):
        self.url = reverse('accounts:change_password')
        self.old_password = "OldPassw0rd!99"
        self.user = make_user(password=self.old_password)
        self.client.force_authenticate(user=self.user)

    def test_change_password_success(self):
        new_password = "NewPassw0rd!99"
        response = self.client.post(self.url, {
            "old_password": self.old_password,
            "new_password": new_password,
            "confirm_password": new_password,
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(new_password))

    def test_change_password_wrong_old_password_rejected(self):
        response = self.client.post(self.url, {
            "old_password": "wrong",
            "new_password": "NewPassw0rd!99",
            "confirm_password": "NewPassw0rd!99",
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_unauthenticated_rejected(self):
        self.client.force_authenticate(user=None)
        response = self.client.post(self.url, {
            "old_password": self.old_password,
            "new_password": "NewPassw0rd!99",
            "confirm_password": "NewPassw0rd!99",
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


# ============================================================
# Two-Factor Authentication Setup Flow Tests
# ============================================================
@override_settings(REST_FRAMEWORK={"DEFAULT_THROTTLE_RATES": PERMISSIVE_THROTTLES})
class TwoFactorSetupFlowTests(APITestCase):
    def setUp(self):
        self.setup_url = reverse('accounts:2fa_setup')
        self.verify_url = reverse('accounts:2fa_verify')
        self.disable_url = reverse('accounts:2fa_disable')
        self.backup_codes_url = reverse('accounts:2fa_backup_codes')
        self.password = "StrongPassw0rd!99"
        self.user = make_user(password=self.password)
        self.client.force_authenticate(user=self.user)

    def test_setup_generates_secret_and_uri(self):
        response = self.client.post(self.setup_url, {"password": self.password}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("secret", response.data["data"])
        self.assertIn("provisioning_uri", response.data["data"])
        tfa = TwoFactorAuth.objects.get(user=self.user)
        self.assertFalse(tfa.enabled)

    def test_setup_wrong_password_rejected(self):
        response = self.client.post(self.setup_url, {"password": "wrong"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_verify_before_setup_rejected(self):
        response = self.client.post(self.verify_url, {"otp_code": "123456"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def _setup_and_enable_2fa(self):
        setup_resp = self.client.post(self.setup_url, {"password": self.password}, format="json")
        secret = setup_resp.data["data"]["secret"]
        code = pyotp.TOTP(secret).now()
        verify_resp = self.client.post(self.verify_url, {"otp_code": code}, format="json")
        self.assertEqual(verify_resp.status_code, status.HTTP_200_OK)
        return secret, verify_resp.data["backup_codes"]

    def test_verify_with_valid_code_enables_2fa_and_returns_backup_codes(self):
        secret, backup_codes = self._setup_and_enable_2fa()
        self.assertEqual(len(backup_codes), 10)
        tfa = TwoFactorAuth.objects.get(user=self.user)
        self.assertTrue(tfa.enabled)
        self.assertEqual(len(tfa.backup_code_hashes), 10)

    def test_verify_with_invalid_code_does_not_enable(self):
        self.client.post(self.setup_url, {"password": self.password}, format="json")
        response = self.client.post(self.verify_url, {"otp_code": "000000"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        tfa = TwoFactorAuth.objects.get(user=self.user)
        self.assertFalse(tfa.enabled)

    def test_disable_requires_password(self):
        self._setup_and_enable_2fa()
        response = self.client.post(self.disable_url, {"password": "wrong"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        response = self.client.post(self.disable_url, {"password": self.password}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        tfa = TwoFactorAuth.objects.get(user=self.user)
        self.assertFalse(tfa.enabled)

    def test_regenerate_backup_codes_invalidates_old_ones(self):
        _, old_codes = self._setup_and_enable_2fa()
        response = self.client.post(self.backup_codes_url, {"password": self.password}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        new_codes = response.data["backup_codes"]
        self.assertNotEqual(set(old_codes), set(new_codes))
        tfa = TwoFactorAuth.objects.get(user=self.user)
        self.assertFalse(tfa.consume_backup_code(old_codes[0]))


# ============================================================
# Two-Factor Login Challenge Tests
# ============================================================
@override_settings(REST_FRAMEWORK={"DEFAULT_THROTTLE_RATES": PERMISSIVE_THROTTLES})
class TwoFactorLoginChallengeTests(APITestCase):
    def setUp(self):
        cache.clear()  # reset throttling counters before each test
        self.login_url = reverse('accounts:login')
        self.challenge_url = reverse('accounts:2fa_login')
        self.password = "StrongPassw0rd!99"
        self.user = make_user(email="2fauser@example.com", password=self.password)
        self.secret = pyotp.random_base32()
        self.tfa = TwoFactorAuth.objects.create(user=self.user)
        self.tfa.enable(self.secret)
        self.backup_codes = ["ABCD123456", "WXYZ987654"]
        self.tfa.set_backup_codes(self.backup_codes)

    def test_challenge_with_correct_password_and_totp_succeeds(self):
        code = pyotp.TOTP(self.secret).now()
        response = self.client.post(self.challenge_url, {
            "email": self.user.email, "password": self.password, "auth_code": code,
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("tokens", response.data)

    def test_challenge_with_correct_backup_code_succeeds_and_consumes_it(self):
        response = self.client.post(self.challenge_url, {
            "email": self.user.email, "password": self.password, "auth_code": self.backup_codes[0],
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Same backup code cannot be reused
        code = pyotp.TOTP(self.secret).now()
        self.tfa.refresh_from_db()
        used_again = self.client.post(self.challenge_url, {
            "email": self.user.email, "password": self.password, "auth_code": self.backup_codes[0],
        }, format="json")
        self.assertEqual(used_again.status_code, status.HTTP_400_BAD_REQUEST)

    def test_challenge_with_wrong_password_fails_even_with_valid_code(self):
        code = pyotp.TOTP(self.secret).now()
        response = self.client.post(self.challenge_url, {
            "email": self.user.email, "password": "totally-wrong-password", "auth_code": code,
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_challenge_with_correct_password_but_wrong_code_fails(self):
        response = self.client.post(self.challenge_url, {
            "email": self.user.email, "password": self.password, "auth_code": "000000",
        }, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_challenge_nonexistent_email_and_wrong_password_give_same_error_shape(self):
        resp_no_user = self.client.post(self.challenge_url, {
            "email": "nobody@example.com", "password": "whatever", "auth_code": "123456",
        }, format="json")
        resp_wrong_pw = self.client.post(self.challenge_url, {
            "email": self.user.email, "password": "wrong", "auth_code": "123456",
        }, format="json")
        self.assertEqual(resp_no_user.status_code, resp_wrong_pw.status_code)
        self.assertEqual(str(resp_no_user.data.get("message")), str(resp_wrong_pw.data.get("message")))

    def test_full_login_flow_requires_both_steps(self):
        login_resp = self.client.post(self.login_url, {"email": self.user.email, "password": self.password}, format="json")
        self.assertEqual(login_resp.status_code, status.HTTP_200_OK)
        self.assertTrue(login_resp.data.get("requires_2fa"))
        self.assertNotIn("tokens", login_resp.data)
        code = pyotp.TOTP(self.secret).now()
        challenge_resp = self.client.post(self.challenge_url, {
            "email": self.user.email, "password": self.password, "auth_code": code,
        }, format="json")
        self.assertEqual(challenge_resp.status_code, status.HTTP_200_OK)
        self.assertIn("tokens", challenge_resp.data)


# ============================================================
# Account Deletion (GDPR) Tests
# ============================================================
@override_settings(REST_FRAMEWORK={"DEFAULT_THROTTLE_RATES": PERMISSIVE_THROTTLES})
class AccountDeletionTests(APITestCase):
    def setUp(self):
        self.request_url = reverse('accounts:account_delete_request')
        self.cancel_url = reverse('accounts:account_delete_cancel')
        self.status_url = reverse('accounts:account_delete_status')
        self.user = make_user()
        self.client.force_authenticate(user=self.user)

    def test_create_deletion_request(self):
        response = self.client.post(self.request_url, {"confirm": True, "reason": "no longer needed"}, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(AccountDeletionRequest.objects.filter(user=self.user, completed=False, cancelled=False).exists())

    def test_create_deletion_request_without_confirm_rejected(self):
        response = self.client.post(self.request_url, {"confirm": False}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_duplicate_deletion_request_rejected(self):
        self.client.post(self.request_url, {"confirm": True}, format="json")
        response = self.client.post(self.request_url, {"confirm": True}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(AccountDeletionRequest.objects.filter(user=self.user).count(), 1)

    def test_cancel_deletion_request(self):
        self.client.post(self.request_url, {"confirm": True}, format="json")
        response = self.client.post(self.cancel_url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        req = AccountDeletionRequest.objects.get(user=self.user)
        self.assertTrue(req.cancelled)

    def test_cancel_without_pending_request_rejected(self):
        response = self.client.post(self.cancel_url, {}, format="json")
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_status_reflects_pending_request(self):
        self.client.post(self.request_url, {"confirm": True}, format="json")
        response = self.client.get(self.status_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data["data"])

    def test_status_none_when_no_request(self):
        response = self.client.get(self.status_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNone(response.data["data"])


# ============================================================
# Throttling Tests (uses REAL rates from settings)
# ============================================================
class ThrottlingTests(APITestCase):
    """Uses the actual configured throttle rates from settings.py.
    Does NOT override with PERMISSIVE_THROTTLES."""
    def setUp(self):
        cache.clear()
        self.login_url = reverse('accounts:login')

    def test_login_endpoint_is_throttled(self):
        statuses = []
        for _ in range(15):
            resp = self.client.post(self.login_url, {"email": "x@example.com", "password": "wrong"}, format="json")
            statuses.append(resp.status_code)
        self.assertIn(status.HTTP_429_TOO_MANY_REQUESTS, statuses)














#=================================== utils.py tests ============================================================================
from django.core import mail
from accounts.otp_logic.utils import (get_email_context,generate_otp,_send_email, send_email_otp,
        send_password_reset_email,get_tokens_for_user, get_client_ip,extract_request_data,api_success)

from rest_framework.response import Response


class UtilsTests(TestCase):

    # Existing Tests
    def test_generate_otp_is_secure_and_correct_length(self):
        otp = generate_otp()
        self.assertEqual(len(otp), 6)
        self.assertTrue(otp.isdigit())

    # Send the email
    def test_send_email_otp_actually_generates_email(self):
        success = send_email_otp(email="test@example.com", otp="123456")
        
        self.assertTrue(success) # Verify function returned True
        
        self.assertEqual(len(mail.outbox), 1) # Verify an email was actually added to Django's outbox
        self.assertEqual(mail.outbox[0].to, ["test@example.com"])
        self.assertIn("123456", mail.outbox[0].body)

    # Create a mock DRF request object  
    def test_get_client_ip_with_proxy(self):
        
        class MockRequest:
            META = {'HTTP_X_FORWARDED_FOR': '192.168.1.100, 10.0.0.1'}
            
        request = MockRequest()
        ip = get_client_ip(request)
        
        self.assertEqual(ip, '192.168.1.100')  # It should extract the first IP in the chain

    # ---------------------------------------------------------
    # New Tests
    # ---------------------------------------------------------
    @override_settings(
        COMPANY_NAME="TestCompany",
        SCHOOL_NAME="TestSchool",
        FRONTEND_URL="http://localhost:3000",
        BACKEND_URL="http://localhost:8000",
        SUPPORT_EMAIL="support@test.com",
        PRIMARY_COLOR="#FFFFFF",
        LOGO_URL="http://logo.com/test.png"
    )
    def test_get_email_context(self):
        """Test that settings are correctly mapped to the email context."""
        context = get_email_context()
        self.assertEqual(context['company_name'], "TestCompany")
        self.assertEqual(context['school_name'], "TestSchool")
        self.assertEqual(context['support_email'], "support@test.com")
        self.assertEqual(context['logo_url'], "http://logo.com/test.png")

    @patch('accounts.otp_logic.utils.EmailMultiAlternatives')
    @patch('accounts.otp_logic.utils.render_to_string')
    def test_send_email_failure_handling(self, mock_render_to_string, mock_email_class):
        """Test that _send_email gracefully returns False if SMTP crashes."""
        # Setup mock to avoid needing real HTML templates for this test
        mock_render_to_string.return_value = "mocked HTML string"
        
        # Force the send() method to raise an Exception
        mock_instance = mock_email_class.return_value
        mock_instance.send.side_effect = Exception("SMTP connection refused")

        result = _send_email(
            email="crash@example.com",
            subject="Will Fail",
            html_template="dummy.html",
            text_template="dummy.txt",
            context={}
        )
        # It should return False instead of raising a 500 server error
        self.assertFalse(result)

    def test_send_password_reset_email(self):
        """Test the password reset specific email sender."""
        success = send_password_reset_email(email="reset@example.com", otp="654321")
        
        self.assertTrue(success)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["reset@example.com"])
        self.assertIn("654321", mail.outbox[0].body)
        self.assertIn("Password Reset", mail.outbox[0].subject)

    def test_get_tokens_for_user(self):
        """Test JWT generation contains required keys."""
        # Create a temporary user in the test database
        user = User.objects.create_user(email="jwt@example.com", password="testpassword123")
        
        tokens = get_tokens_for_user(user)
        
        self.assertIn("access", tokens)
        self.assertIn("refresh", tokens)
        self.assertIn("jti", tokens)
        
        self.assertTrue(isinstance(tokens["access"], str))
        self.assertTrue(len(tokens["jti"]) > 0)

    def test_get_client_ip_without_proxy(self):
        """Test IP extraction during local development (no X-Forwarded-For)."""
        class MockRequest:
            META = {'REMOTE_ADDR': '127.0.0.1'}
            
        request = MockRequest()
        ip = get_client_ip(request)
        
        self.assertEqual(ip, '127.0.0.1')

    def test_extract_request_data(self):
        """Test extraction of user device and location metadata."""
        class MockRequest:
            META = {
                'HTTP_USER_AGENT': 'Mozilla/5.0 (Windows NT 10.0)',
                'REMOTE_ADDR': '192.168.1.55'
            }
            # Simulate parsed JSON body
            data = {
                'device_name': 'Desktop PC',
                'browser': 'Chrome',
                'operating_system': 'Windows 11',
                'location': 'Peshawar',
                'device_id': 'device-xyz-123'
            }
            
        request = MockRequest()
        result = extract_request_data(request)
        
        self.assertEqual(result['ip_address'], '192.168.1.55')
        self.assertEqual(result['user_agent'], 'Mozilla/5.0 (Windows NT 10.0)')
        self.assertEqual(result['device_name'], 'Desktop PC')
        self.assertEqual(result['location'], 'Peshawar')

    def test_api_success(self):
        """Test API standard response generator."""
        # Test with custom data and status code
        response = api_success(message="Login successful", data={"user_id": 1}, status_code=201)
        
        self.assertIsInstance(response, Response)
        self.assertEqual(response.status_code, 201)
        self.assertTrue(response.data['success'])
        self.assertEqual(response.data['message'], "Login successful")
        self.assertEqual(response.data['data']['user_id'], 1)
        
        # Test with default arguments
        response_default = api_success(message="Logged out")
        self.assertEqual(response_default.status_code, 200)
        self.assertEqual(response_default.data['data'], {})