from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('register/', views.register_view, name='register'),
    path('refresh/', views.refresh_token_view, name='refresh_token'),
    path('user/me/', views.get_current_user, name='current_user'),
]