from urllib import request
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer, LoginSerializer, EmailSerializer, NewPasswordSerializer
from .models import User
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from drf_spectacular.utils import extend_schema
from rest_framework.views import APIView
from .permissions import IsAdminUserCustom, IsVerifiedUser
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.conf import settings


@extend_schema(
    description="Register a new user by providing email, full name, and password. Password must be at least 6 characters long.",
    tags=["Authentication"],
)
class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()

        token_generator = PasswordResetTokenGenerator()
        token = token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))

        # Build base URL from the current request (works on Render)
        base_url = self.request.build_absolute_uri("/")[:-1]  # e.g. https://yourapp.onrender.com
        verification_link = f"{base_url}/api/auth/verify/{uid}/{token}/"

        print("Verification Link:", verification_link)


@extend_schema(
    description="Verify user email address using the verification link sent during registration.",
    tags=["Authentication"],
    )
class VerifyEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({"error": "Invalid link"}, status=400)

        token_generator = PasswordResetTokenGenerator()

        if token_generator.check_token(user, token):
            user.is_verified = True
            user.save()
            return Response({
                "success": True,
                "message": "Email verified successfully",
                "data": None
            })
        else:
            return Response({
                "success": False,
                "message": "Invalid or expired token",
                "data": None
            }, status=400)

@extend_schema(
    description="Login with registered email and password to receive JWT access and refresh tokens.",
    tags=["Authentication"],
)  
@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='post')
class LoginView(generics.GenericAPIView):
    serializer_class = LoginSerializer
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data

        refresh = RefreshToken.for_user(user)

        return Response({
            "success": True,
            "message": "Login successful",
            "data": {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }
        })

@extend_schema(
    description="Access a protected endpoint that requires authentication.",
    tags=["Authentication"],
)
class ProtectedView(generics.GenericAPIView):
    permission_classes = [IsVerifiedUser]

    def get(self, request):
        return Response({
            "success": True,
            "message": "You are authenticated and verified!",
            "data": None
        })

@extend_schema(
    description="Request a password reset link by providing the registered email address.",
    tags=["Authentication"],
    request=EmailSerializer,
)
class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = EmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        user = User.objects.filter(email=email).first()

        if user:
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            base_url = self.request.build_absolute_uri("/")[:-1]
            reset_link = f"{base_url}/api/auth/reset-password/{uid}/{token}/"
            print("Password Reset Link:", reset_link)

        # Always return same response
        return Response(
            {
                "success": True,
                "message": "If this email exists, a reset link has been sent.",
                "data": None
            },
            status=200
        )

@extend_schema(
    description="Reset password using the link sent to email. Provide new password in the request body.",
    tags=["Authentication"],
    request=NewPasswordSerializer,
)
class ResetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        serializer = NewPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        new_password = serializer.validated_data["password"]

        if not new_password:
            return Response({"error": "Password is required"}, status=400)

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except Exception:
            return Response({"error": "Invalid link"}, status=400)

        token_generator = PasswordResetTokenGenerator()

        if not token_generator.check_token(user, token):
            return Response({"error": "Invalid or expired token"}, status=400)

        # Validate password strength
        try:
            validate_password(new_password, user)
        except ValidationError as e:
            return Response({"error": list(e.messages)}, status=400)

        user.set_password(new_password)
        user.save()

        return Response({
            "success": True,
            "message": "Password reset successful",
            "data": None
        })


class AdminOnlyView(APIView):
    permission_classes = [IsAdminUserCustom]

    def get(self, request):
        return Response({
            "success": True,
            "message": "Welcome Admin!",
            "data": None
        })