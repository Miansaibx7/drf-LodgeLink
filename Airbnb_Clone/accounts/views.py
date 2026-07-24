import logging
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny,IsAuthenticated

from rest_framework.throttling import AnonRateThrottle, UserRateThrottle # ratelimit

from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework import status

from django.contrib.auth.models import update_last_login

from .otp_logic.services import register_user, OTPService, authenticate_user, handle_successful_login
from .sub_views.two_factor import TwoFactorService

from .serializers import (
    RegisterSerializer, LoginSerializer, EmailOTPSendSerializer,
    EmailOTPVerifySerializer, ResendEmailOTPSerializer,
    PasswordResetOTPSendSerializer, PasswordResetOTPVerifySerializer,
    ChangePasswordSerializer, GoogleLoginSerializer, GitHubLoginSerializer,
    FacebookLoginSerializer, LinkedInLoginSerializer, LogoutSerializer,
)

from .otp_logic.utils import  get_tokens_for_user

from .models import UserSession, AuditLog
from .exceptions import ServiceLayerError

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError


logger = logging.getLogger(__name__)


# --- Custom Throttles ---
# These protect your OTP and Login endpoints from brute-force and SMS/Email bombing attacks.
class OTPRateThrottle(AnonRateThrottle):
    scope = 'otp_requests'

class LoginRateThrottle(AnonRateThrottle):
    scope = 'login_requests'

class RegisterRateThrottle(AnonRateThrottle):
    # FIX: RegisterView previously reused LoginRateThrottle's scope
    # ('login_requests'). That conflates two very different abuse patterns
    # (credential-stuffing vs. mass fake-account creation) under one budget,
    # and a burst of registrations would eat into legitimate users' login
    # attempts (they share the same throttle cache key namespace... actually
    # DRF scopes them by (scope, ident), so it's not a shared *bucket*, but
    # it's still the wrong semantic scope and rate). Registration gets its
    # own scope so its rate can be tuned independently. Add
    # 'register_requests' to DEFAULT_THROTTLE_RATES in settings.py.
    scope = 'register_requests'

def _extract_request_data(request: Request) -> dict:
    """Extract IP, user-agent, and other metadata from request."""
    return {
        'ip_address': request.META.get('REMOTE_ADDR'),
        'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        'device_name': request.data.get('device_name', ''),
        'browser': request.data.get('browser', ''),
        'operating_system': request.data.get('operating_system', ''),
        'location': request.data.get('location', ''),
        'device_id': request.data.get('device_id', ''),
    }



class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [RegisterRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = RegisterSerializer(data=request.data)
        # Automatically handles 400 errors if data is invalid
        serializer.is_valid(raise_exception=True)

        # Passing only validated data as kwargs to the service layer.
        # The service layer now has zero dependency on DRF serializers.
        request_data = _extract_request_data(request)
        register_user(
                    email=serializer.validated_data['email'],
                    password=serializer.validated_data['password'],
                    request_data=request_data,
                    **{k: v for k, v in serializer.validated_data.items()
                       if k not in ('confirm_password', 'terms_accepted', 'email', 'password')}
                )
        
        return Response(
            {"success": True, "message": "Registration successful. Please check your email for the verification OTP."},
            status=status.HTTP_201_CREATED
        )



class LoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = LoginSerializer(data=request.data, context={"request": request})
        #  This automatically handles invalid credentials and unverified users.
        # It will throw a 400 Bad Request if anything fails.
        serializer.is_valid(raise_exception=True)
        
        # Grab the user object that we safely attached inside the serializer
        # We bypass the serializer's validation for email/password because we handle it in the service
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        request_data = _extract_request_data(request)

        # Authenticate with brute‑force protection
        # FIX (bug): this used to call authenticate_user() a SECOND time after
        # LoginSerializer.validate() already ran Django's authenticate()
        # internally — i.e. two full password-hash comparisons per login, and
        # two divergent code paths for "is this login allowed" (the serializer
        # version didn't touch LoginAttempt at all). All auth + brute-force
        # logic now lives in this one service call.
        user = authenticate_user(email, password, request_data)
    
        # FIX (missing feature): TwoFactorLoginView existed in
        # sub_views/two_factor.py but nothing ever routed a normal login
        # through it — a user with 2FA enabled would get a full access/refresh
        # token pair from a bare email+password POST, i.e. 2FA was decorative.
        # Now: if 2FA is enabled, we do NOT issue tokens here. The client must
        # call /2fa/login/ with the TOTP/backup code to get tokens.
        tfa = getattr(user, 'two_factor_auth', None)
        if tfa is not None and tfa.enabled:
            return Response({"success": True,"message": "Password verified. Two-factor authentication code required.",
                    "requires_2fa": True,"email": user.email},
                status=status.HTTP_200_OK)

        tokens = get_tokens_for_user(user) # Generate JWT Tokens and log success
        refresh_jti = tokens['jti']

        handle_successful_login(user, request_data, refresh_jti) # Create session, update device, log login
        update_last_login(None, user) # Update last login time

        logger.info("User %s logged in successfully.", user.email)

        return Response({"success": True, "message": "Login successful.", "tokens": tokens,
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.get_full_name() or user.email,
                "is_verified": user.is_verified
            }
        }, status=status.HTTP_200_OK)       



class EmailOTPSendView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = EmailOTPSendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        request_data = _extract_request_data(request)
        OTPService.send_email_otp(serializer.validated_data["email"], request_data)

        return Response({"success": True, "message": "OTP sent successfully."}, status=status.HTTP_200_OK)



class EmailOTPVerifyView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = EmailOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        request_data = _extract_request_data(request)
        OTPService.verify_email_otp(**serializer.validated_data, request_data=request_data)

        return Response({"success": True, "message": "Email verified successfully."}, status=status.HTTP_200_OK)



class ResendEmailOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = ResendEmailOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        request_data = _extract_request_data(request)
        OTPService.resend_email_otp(serializer.validated_data["email"], request_data)

        return Response({"success": True, "message": "OTP resent successfully."}, status=status.HTTP_200_OK)
        


class PasswordResetOTPSendView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = PasswordResetOTPSendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
    
        request_data = _extract_request_data(request)
        OTPService.send_password_reset_otp(serializer.validated_data["email"], request_data)

        return Response({"success": True, "message": "Password reset OTP sent successfully."}, status=status.HTTP_200_OK)

        


class PasswordResetOTPVerifyView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = PasswordResetOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        request_data = _extract_request_data(request)
        OTPService.verify_password_reset_otp(**serializer.validated_data, request_data=request_data)

        return Response({"success": True, "message": "Password reset successfully."}, status=status.HTTP_200_OK)



class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    # Authenticated endpoints use UserRateThrottle instead of AnonRateThrottle
    throttle_classes = [UserRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        
        request_data = _extract_request_data(request)
        OTPService.change_password(
            user=request.user,
            old_password=serializer.validated_data["old_password"],
            new_password=serializer.validated_data["new_password"],
            request_data=request_data,
        )

        return Response({"success": True, "message": "Password changed successfully."}, status=status.HTTP_200_OK)

        


class BaseOAuthLoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]
    serializer_class = None

    def post(self, request: Request) -> Response:

        # DEFENSIVE PROGRAMMING: Ensure subclasses define a serializer
        assert self.serializer_class is not None, (
            f"'{self.__class__.__name__}' must define a `serializer_class`."
        )
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        request_data = _extract_request_data(request)

        # Generate tokens
        tokens = get_tokens_for_user(user)
        refresh_jti = tokens['jti']

        # Create session, update device, log login
        handle_successful_login(user, request_data, refresh_jti)

        update_last_login(None, user)
        logger.info("OAuth login successful for %s", user.email)

        return Response({"success": True, "message": "Login successful.", "tokens": tokens,
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.get_full_name() or user.email,
                "is_verified": user.is_verified
            }
        }, status=status.HTTP_200_OK)
   


class GoogleLoginView(BaseOAuthLoginView):
    serializer_class = GoogleLoginSerializer


class GitHubLoginView(BaseOAuthLoginView):
    serializer_class = GitHubLoginSerializer


class FacebookLoginView(BaseOAuthLoginView):
    serializer_class = FacebookLoginSerializer


class LinkedInLoginView(BaseOAuthLoginView):
    serializer_class = LinkedInLoginSerializer




class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Blacklist token
        serializer.save()

        # Mark active session as inactive
        # We need to find the session associated with the current refresh token
        # The refresh token JTI is stored in the session.
        # The client should send the refresh token in the request; we can extract JTI from it.
        # But we don't have the session ID. We can query session by refresh_token_jti.
        refresh_token = request.data.get('refresh')
        if refresh_token:
            
            try:
                token = RefreshToken(refresh_token)
                jti = token['jti']
                session = UserSession.objects.filter(refresh_token_jti=jti, user=request.user, is_active=True).first()
                if session:
                    session.logout()
            except TokenError:
                # FIX (bug): the original `except Exception: pass` silently
                # swallowed EVERYTHING, including programming errors (e.g. a
                # typo'd attribute access) — you'd never see it in logs. We
                # now only swallow the specific, expected failure (a malformed
                # / already-invalid token, which just means we can't look up
                # the session — logout still proceeds) and log it, and let any
                # other exception type propagate to the global exception
                # handler so it's actually visible.
                logger.warning("Could not resolve session for refresh token during logout.", exc_info=True)
        # Log logout
        AuditLog.objects.create(
            user=request.user,
            action="LOGOUT",
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )

        logger.info("User %s logged out successfully.", request.user.email)
        return Response({"success": True, "message": "Logout successful."}, status=status.HTTP_200_OK)