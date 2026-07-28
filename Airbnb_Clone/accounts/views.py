import logging
from rest_framework.views import APIView

from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle # ratelimit

from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework import status

from django.contrib.auth.models import update_last_login

from .otp_logic.services import register_user, OTPService, authenticate_user, handle_successful_login

from .serializers import (
    RegisterSerializer, LoginSerializer, EmailOTPSendSerializer,
    EmailOTPVerifySerializer, ResendEmailOTPSerializer,
    PasswordResetOTPSendSerializer, PasswordResetOTPVerifySerializer,
    ChangePasswordSerializer, GoogleLoginSerializer, GitHubLoginSerializer,
    FacebookLoginSerializer, LinkedInLoginSerializer, LogoutSerializer,
)

# Imported the helper function from utils
from .otp_logic.utils import get_client_ip, get_tokens_for_user, extract_request_data 

from .models import UserSession, AuditLog

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
    # Registration gets its own scope so its rate can be tuned independently. Add
    # 'register_requests' to DEFAULT_THROTTLE_RATES in settings.py.
    scope = 'register_requests'



class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [RegisterRateThrottle]

    def post(self, request: Request) -> Response:
        serializer = RegisterSerializer(data=request.data)
        # Automatically handles 400 errors if data is invalid
        serializer.is_valid(raise_exception=True)

        # Passing only validated data as kwargs to the service layer.
        # The service layer now has zero dependency on DRF serializers.
        request_data = extract_request_data(request)
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
        serializer.is_valid(raise_exception=True) # It will throw a 400 Bad Request if anything fails.

        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        request_data = extract_request_data(request)

        # Service layer handles brute-force protection and authentication
        user = authenticate_user(email, password, request_data)
    
        # Route 2FA users to the correct secondary verification endpoint
        tfa = getattr(user, 'two_factor_auth', None)
        if tfa is not None and tfa.enabled:
            return Response({"success": True, "message": "Password verified. Two-factor authentication code required.",
                    "requires_2fa": True, "email": user.email},
                status=status.HTTP_200_OK
            )

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
            },status=status.HTTP_200_OK)



class EmailOTPSendView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = EmailOTPSendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        request_data = extract_request_data(request)
        OTPService.send_email_otp(serializer.validated_data["email"], request_data)

        return Response({"success": True, "message": "OTP sent successfully."}, status=status.HTTP_200_OK)



class EmailOTPVerifyView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = EmailOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        request_data = extract_request_data(request)
        OTPService.verify_email_otp(**serializer.validated_data, request_data=request_data)

        return Response({"success": True, "message": "Email verified successfully."}, status=status.HTTP_200_OK)



class ResendEmailOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = ResendEmailOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        request_data = extract_request_data(request)
        OTPService.resend_email_otp(serializer.validated_data["email"], request_data)

        return Response({"success": True, "message": "OTP resent successfully."}, status=status.HTTP_200_OK)
        


class PasswordResetOTPSendView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = PasswordResetOTPSendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
    
        request_data = extract_request_data(request)
        OTPService.send_password_reset_otp(serializer.validated_data["email"], request_data)

        return Response({"success": True, "message": "Password reset OTP sent successfully."}, status=status.HTTP_200_OK)

        


class PasswordResetOTPVerifyView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = PasswordResetOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        request_data = extract_request_data(request)
        OTPService.verify_password_reset_otp(**serializer.validated_data, request_data=request_data)

        return Response({"success": True, "message": "Password reset successfully."}, status=status.HTTP_200_OK)



class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    # Authenticated endpoints use UserRateThrottle instead of AnonRateThrottle
    throttle_classes = [UserRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        
        request_data = extract_request_data(request)
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

        # Ensure subclasses define a serializer
        if self.serializer_class is None:
            raise NotImplementedError(f"'{self.__class__.__name__}' must define a `serializer_class`.")

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        request_data = extract_request_data(request)

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
                # Safely get 'jti' to prevent 500 KeyError crashes
                jti = token.get('jti') 
                if jti:
                    session = UserSession.objects.filter(refresh_token_jti=jti, user=request.user, is_active=True).first()

                    if session:
                        session.logout()
                
            except TokenError:
                # Expected failure for malformed/expired tokens. 
                # Logout still proceeds.
                logger.warning("Could not resolve session for refresh token during logout.", exc_info=True)
        # Log logout using the secure IP extraction
        AuditLog.objects.create(
            user=request.user,
            action=AuditLog.Action.LOGOUT,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )

        logger.info("User %s logged out successfully.", request.user.email)
        return Response({"success": True, "message": "Logout successful."}, status=status.HTTP_200_OK)