
import logging
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny,IsAuthenticated

from rest_framework.response import Response
from rest_framework import status, serializers

from django.contrib.auth import update_last_login

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
                        LinkedInLoginSerializer
                        )

from .otp_logic.utils import  get_tokens_for_user


logger = logging.getLogger(__name__)


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request)-> Response:
        serializer = RegisterSerializer(data=request.data)
        # Automatically handles 400 errors if data is invalid
        serializer.is_valid(raise_exception=True)

        try:
            register_user(serializer)
            # If we reach here, the transaction is committed successfully
            return Response({"success": True,"message": "Registration successful. Please check your email for the verification OTP."},
                status=status.HTTP_201_CREATED)
        except serializers.ValidationError:
            raise

        except Exception:
            logger.exception("Unexpected error during registration.")

            return Response({"success": False,"message": "An unexpected error occurred. Please try again later.",},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request)-> Response:
        try:
            serializer = LoginSerializer(data=request.data,context={"request": request})

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

            return Response(
                {
                    "success": True,
                    "message": "Login successful.",
                    "tokens": tokens,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "name": user.name,
                        "is_verified": user.is_verified,
                    },
                },
                status=status.HTTP_200_OK,
            )

        except serializers.ValidationError:
            raise

        except Exception:
            logger.exception("Unexpected error during login.")

            return Response({"success": False,"message": ("An unexpected error occurred. ""Please try again later.")},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,)
        


class EmailOTPSendView(APIView):
    permission_classes = [AllowAny]

    def post(self, request) -> Response:

        serializer = EmailOTPSendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            OTPService.send_email_otp(serializer.validated_data["email"])
            return Response({"success": True,"message": "OTP sent successfully.",},status=status.HTTP_200_OK,)
        except serializers.ValidationError:
            raise

        except Exception:
            logger.exception("Unexpected error while sending OTP.")

            return Response({"success": False,"message": "An unexpected error occurred. Please try again later.",},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,)



class EmailOTPVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request) -> Response:
        serializer = EmailOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            OTPService.verify_email_otp(**serializer.validated_data)
            return Response({"success": True,"message": "Email verified successfully.",},status=status.HTTP_200_OK)
        except serializers.ValidationError:
            raise

        except Exception:
            logger.exception("Unexpected error during email verification.")

            return Response({"success": False,"message": "An unexpected error occurred. Please try again later.",},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class ResendEmailOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request)-> Response:
        serializer = ResendEmailOTPSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        try:
            OTPService.resend_email_otp(serializer.validated_data["email"])
            return Response({"success": True,"message": "OTP resent successfully."},status=status.HTTP_200_OK)
        except serializers.ValidationError:
            raise

        except Exception:
            logger.exception("Unexpected error while resending OTP.")

            return Response({"success": False,"message": "An unexpected error occurred. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class PasswordResetOTPSendView(APIView):
    permission_classes = [AllowAny]

    def post(self, request) -> Response:
        serializer = PasswordResetOTPSendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            OTPService.send_password_reset_otp(serializer.validated_data["email"])
            return Response({"success": True,"message": ("Password reset OTP sent successfully.")},status=status.HTTP_200_OK,)
        except serializers.ValidationError:
            raise

        except Exception:
            logger.exception("Unexpected error while sending password reset OTP.")

            return Response({"success": False,"message": ("An unexpected error occurred. " "Please try again later.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class PasswordResetOTPVerifyView(APIView):
    permission_classes = [AllowAny]

    def post(self, request)-> Response:
        serializer = PasswordResetOTPVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            OTPService.verify_password_reset_otp(**serializer.validated_data)
            return Response({"success": True,"message": "Password reset successfully."},status=status.HTTP_200_OK)
        except serializers.ValidationError:
            raise

        except Exception:
            logger.exception("Unexpected error during password reset verification.")

            return Response({"success": False,"message": "An unexpected error occurred. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        try:
            OTPService.change_password()
        except serializers.ValidationError:
            raise
    def post(self, request) -> Response:
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            OTPService.change_password(user=request.user,
                old_password=serializer.validated_data["old_password"],
                new_password=serializer.validated_data["new_password"],
            )
            return Response({"success": True,"message": "Password changed successfully."},status=status.HTTP_200_OK)
        except serializers.ValidationError:
            raise

        except Exception:
            logger.exception("Unexpected error while changing password.")

            return Response({"success": False,"message": ("An unexpected error occurred. ""Please try again later.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        


class BaseOAuthLoginView(APIView):
    permission_classes = [AllowAny]
    serializer_class = None

    def post(self, request)-> Response:
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            user = serializer.validated_data["user"]
            update_last_login(None,user)
            tokens = get_tokens_for_user(user)
            logger.info("OAuth login successful for %s",user.email)

            return Response({"success": True,"message": "Login successful.","tokens": tokens,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "name": user.name,
                        "is_verified": user.is_verified,
                    },
                },status=status.HTTP_200_OK)
        except serializers.ValidationError:
            raise

        except Exception:
            logger.exception("Unexpected OAuth login error.")

            return Response({"success": False,"message": ("An unexpected error occurred. ""Please try again later.")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class GoogleLoginView(BaseOAuthLoginView):
    serializer_class = GoogleLoginSerializer


class GitHubLoginView(BaseOAuthLoginView):
    serializer_class = GitHubLoginSerializer


class FacebookLoginView(BaseOAuthLoginView):
    serializer_class = FacebookLoginSerializer
    