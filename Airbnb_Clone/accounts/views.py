
import logging
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny,IsAuthenticated

from rest_framework.throttling import AnonRateThrottle, UserRateThrottle # ratelimit

from rest_framework.response import Response
from rest_framework.request import Request
from rest_framework import status, serializers

from django.contrib.auth.models import update_last_login

from .otp_logic.services import register_user, OTPService

from .serializers import (RegisterSerializer,
                        LoginSerializer,
                        EmailOTPSendSerializer,
                        EmailOTPVerifySerializer,
                        ResendEmailOTPSerializer,
                        PasswordResetOTPSendSerializer,
                        PasswordResetOTPVerifySerializer,
                        ChangePasswordSerializer,
                        GoogleLoginSerializer,
                        GitHubLoginSerializer,
                        FacebookLoginSerializer,
                        LinkedInLoginSerializer,
                        LogoutSerializer
                        )

from .otp_logic.utils import  get_tokens_for_user


logger = logging.getLogger(__name__)


# --- Custom Throttles ---
# These protect your OTP and Login endpoints from brute-force and SMS/Email bombing attacks.
class OTPRateThrottle(AnonRateThrottle):
    scope = 'otp_requests'

class LoginRateThrottle(AnonRateThrottle):
    scope = 'login_requests'



class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = RegisterSerializer(data=request.data)
        # Automatically handles 400 errors if data is invalid
        serializer.is_valid(raise_exception=True)

        # Passing only validated data as kwargs to the service layer.
        # The service layer now has zero dependency on DRF serializers.
        register_user(**serializer.validated_data)
        
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
        user = serializer.validated_data["user"]

        # Update last login time
        update_last_login(None, user)

        # Generate JWT Tokens and log success
        tokens = get_tokens_for_user(user)

        logger.info("User %s logged in successfully.", user.email)

        return Response({"success": True,"message": "Login successful.","tokens": tokens,
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "name": getattr(user, 'name', ''), # Use getattr in case name isn't on base model
                    "is_verified": getattr(user, 'is_verified', True)
                },
            },status=status.HTTP_200_OK
        )
        


class EmailOTPSendView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = EmailOTPSendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        OTPService.send_email_otp(serializer.validated_data["email"])
        
        return Response({"success": True, "message": "OTP sent successfully."},status=status.HTTP_200_OK)



class EmailOTPVerifyView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = EmailOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        OTPService.verify_email_otp(**serializer.validated_data)
        
        return Response({"success": True, "message": "Email verified successfully."},status=status.HTTP_200_OK)



class ResendEmailOTPView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = ResendEmailOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        OTPService.resend_email_otp(serializer.validated_data["email"])
        
        return Response({"success": True, "message": "OTP resent successfully."},status=status.HTTP_200_OK)
        


class PasswordResetOTPSendView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = PasswordResetOTPSendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        OTPService.send_password_reset_otp(serializer.validated_data["email"])
        
        return Response({"success": True, "message": "Password reset OTP sent successfully."},status=status.HTTP_200_OK)
        


class PasswordResetOTPVerifyView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [OTPRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = PasswordResetOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        OTPService.verify_password_reset_otp(**serializer.validated_data)
        
        return Response({"success": True, "message": "Password reset successfully."},status=status.HTTP_200_OK)



class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    # Authenticated endpoints use UserRateThrottle instead of AnonRateThrottle
    throttle_classes = [UserRateThrottle]

    def post(self, request: Request) -> Response:

        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        
        OTPService.change_password(user=request.user,
            old_password=serializer.validated_data["old_password"],
            new_password=serializer.validated_data["new_password"]
        )
        
        return Response({"success": True, "message": "Password changed successfully."},status=status.HTTP_200_OK)
        


class BaseOAuthLoginView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [LoginRateThrottle]
    serializer_class = None

    def post(self, request: Request) -> Response:

        # DEFENSIVE PROGRAMMING: Ensure subclasses define a serializer
        assert self.serializer_class is not None, (
            f"'{self.__class__.__name__}' must define a `serializer_class` attribute."
        )

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user = serializer.validated_data["user"]
        update_last_login(None, user)
        tokens = get_tokens_for_user(user)
        logger.info("OAuth login successful for %s", user.email)

        return Response({"success": True,"message": "Login successful.","tokens": tokens,
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "name": getattr(user, 'name', ''),
                    "is_verified": getattr(user, 'is_verified', True)
                },
            },
            status=status.HTTP_200_OK
        )
    


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

        serializer.save()
        logger.info("User %s logged out successfully.", request.user.email)
        
        return Response(
            {"success": True, "message": "Logout successful."},
            status=status.HTTP_200_OK
        )