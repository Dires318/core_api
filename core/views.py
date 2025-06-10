from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model, authenticate
from django.conf import settings
from django.views.decorators.csrf import ensure_csrf_cookie
from datetime import datetime, timedelta

User = get_user_model()

def set_auth_cookies(response, access_token, refresh_token):
    """Helper function to set auth cookies"""
    # Set access token cookie
    response.set_cookie(
        'access_token',
        str(access_token),
        expires=datetime.now() + timedelta(minutes=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'].minutes),
        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
        path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH']
    )
    
    # Set refresh token cookie
    response.set_cookie(
        'refresh_token',
        str(refresh_token),
        expires=datetime.now() + timedelta(days=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].days),
        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
        path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH']
    )

def unset_auth_cookies(response):
    """Helper function to unset auth cookies"""
    response.delete_cookie('access_token')
    response.delete_cookie('refresh_token')

@api_view(['POST'])
@permission_classes([AllowAny])  # Allow unauthenticated access
@ensure_csrf_cookie
def login_view(request):
    username = request.data.get('username')
    password = request.data.get('password')
    
    if not username or not password:
        return Response(
            {'detail': 'Please provide both username and password.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user = authenticate(username=username, password=password)
    
    if user is None:
        return Response(
            {'detail': 'Invalid credentials.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    refresh = RefreshToken.for_user(user)
    response = Response({
        'detail': 'Successfully logged in.',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'middle_name': user.middle_name
        }
    })
    
    # Set access token cookie
    response.set_cookie(
        'access_token',
        str(refresh.access_token),
        expires=datetime.now() + settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
        path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH'],
        domain=None  # Allow cookies to work on localhost
    )
    
    # Set refresh token cookie
    response.set_cookie(
        'refresh_token',
        str(refresh),
        expires=datetime.now() + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
        path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH'],
        domain=None  # Allow cookies to work on localhost
    )
    
    # Set CSRF token cookie
    response.set_cookie(
        'csrftoken',
        request.META.get('CSRF_COOKIE', ''),
        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
        httponly=False,  # CSRF token needs to be accessible by JavaScript
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
        path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH'],
        domain=None  # Allow cookies to work on localhost
    )
    
    return response

@api_view(['POST'])
@ensure_csrf_cookie
@permission_classes([AllowAny])
def logout_view(request):
    refresh_token = request.COOKIES.get('refresh_token')
    if refresh_token:
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            response = Response({'detail': 'Successfully logged out.'})
            unset_auth_cookies(response)
            return response
        except Exception as e:
            print(e)
            return Response(
                {'detail': 'Error during logout.'},
                status=status.HTTP_400_BAD_REQUEST
            )
    else:
        return Response(
            {'detail': 'No refresh token found.'},
            status=status.HTTP_200_OK
        )

@api_view(['POST'])
@permission_classes([AllowAny])  # Allow unauthenticated access
@ensure_csrf_cookie
def register_view(request):
    username = request.data.get('username')
    password = request.data.get('password')
    email = request.data.get('email')
    first_name = request.data.get('first_name')
    middle_name = request.data.get('middle_name')
    last_name = request.data.get('last_name')
    
    if not all([username, password, email]):
        return Response(
            {'detail': 'Please provide all required fields.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if User.objects.filter(username=username).exists():
        return Response(
            {'detail': 'Username already exists.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    if User.objects.filter(email=email).exists():
        return Response(
            {'detail': 'Email already exists.'},
            status=status.HTTP_400_BAD_REQUEST
        )
    
    user = User.objects.create_user(
        username=username,
        email=email,
        password=password,
        first_name=first_name or '',
        last_name=last_name or '',
        middle_name=middle_name or ''
    )
    
    refresh = RefreshToken.for_user(user)
    response = Response({
        'detail': 'Successfully registered.',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name
        }
    })
    
    # Set cookies with proper configuration
    response.set_cookie(
        'access_token',
        str(refresh.access_token),
        expires=datetime.now() + settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
        path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH'],
        domain=None  # Allow cookies to work on localhost
    )
    
    response.set_cookie(
        'refresh_token',
        str(refresh),
        expires=datetime.now() + settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
        secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
        httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
        samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE'],
        path=settings.SIMPLE_JWT['AUTH_COOKIE_PATH'],
        domain=None  # Allow cookies to work on localhost
    )
    
    return response

@api_view(['POST'])
@permission_classes([AllowAny])  # Allow unauthenticated access
@ensure_csrf_cookie
def refresh_token_view(request):
    try:
        refresh_token = request.COOKIES.get('refresh_token')
        if not refresh_token:
            return Response(
                {'detail': 'No refresh token found.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        token = RefreshToken(refresh_token)
        response = Response({'detail': 'Token refreshed successfully.'})
        
        set_auth_cookies(response, token.access_token, token)
        
        return response
    except Exception as e:
        return Response(
            {'detail': 'Invalid refresh token.'},
            status=status.HTTP_400_BAD_REQUEST
        )

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_current_user(request):
    """Get the current authenticated user's information"""
    user = request.user
    return Response({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'last_name': user.last_name,
        'middle_name': user.middle_name,
        'date_joined': user.date_joined,
        'last_login': user.last_login
    })
