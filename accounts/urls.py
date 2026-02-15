from django.urls import path
from .views import RegisterView, LoginView, ProtectedView, VerifyEmailView, ForgotPasswordView, ResetPasswordView, AdminOnlyView, ResendVerificationView
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('register/', RegisterView.as_view()),
    path('verify/<uidb64>/<token>/', VerifyEmailView.as_view()),
    path('resend-verification/', ResendVerificationView.as_view()),
    path('login/', LoginView.as_view()),
    path('forgot-password/', ForgotPasswordView.as_view()),
    path('reset-password/<uidb64>/<token>/', ResetPasswordView.as_view()),
    path('token/refresh/', TokenRefreshView.as_view()),
    path('protected/', ProtectedView.as_view()),
    path('admin-only/', AdminOnlyView.as_view()),
]
