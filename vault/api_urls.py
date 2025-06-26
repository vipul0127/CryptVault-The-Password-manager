from django.urls import path
from . import views

urlpatterns = [
    path('api/login/', views.api_login, name='api_login'),
    path('api/password-search/', views.password_search_api, name='password_search_api'),
]