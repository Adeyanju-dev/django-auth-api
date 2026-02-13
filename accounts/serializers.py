from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate, get_user_model
from drf_spectacular.utils import extend_schema_serializer, OpenApiExample

@extend_schema_serializer(
    examples=[
        OpenApiExample(
            'Register Example',
            summary='Example for registering a user',
            description='Shows how to create a new user',
            value={
                "email": "john@example.com",
                "full_name": "John Doe",
                "password": "password123"
            },
            request_only=True
        )
    ]
)
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6, help_text="Password must be at least 6 characters long.")

    class Meta:
        model = User
        fields = ('email', 'full_name', 'password')
        extra_kwargs = {
            'email': {'help_text': "User email address, must be unique"},
            'full_name': {'help_text': "User's full name"},
        }

    def create(self, validated_data):
        """Create and return a new user"""
        return User.objects.create_user(**validated_data)


@extend_schema_serializer(
    examples=[
        OpenApiExample(
            'Login Example',
            summary='Example for logging in a user',
            description='Shows how to authenticate a user and receive JWT tokens',
            value={
                "email": "john@example.com",
                "password": "password123"
            },
            request_only=True
        )
    ]
)
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(help_text="Registered email address")
    password = serializers.CharField(write_only=True, help_text="User password")

    def validate(self, data):
        user = authenticate(
            email=data['email'],
            password=data['password']
        )

        if not user:
            raise serializers.ValidationError("Invalid credentials")

        if not user.is_verified:
            raise serializers.ValidationError("Email is not verified")

        return user
    
class EmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

class NewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=8, write_only=True)
