from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

urlpatterns = [
    path('api/health/', views.health_check, name='health_check'),
    path('register/', views.register_first_user, name='register'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('extension_guide/', views.extension_guide, name='extension_guide'),
    path('privacy/', views.privacy, name='privacy'),
    path('share/', views.share, name='share'),
    path('', views.index_redirect, name='index'),
    path('welcome/', views.welcome, name='welcome'),
    path('vault_home/', views.vault_home, name='vault_home'),
    path('steg_images/<int:entry_id>/', views.steg_image_list, name='steg_image_list'),
    path('add/', views.vault_add, name='vault_add'),
    path('edit/<int:pk>/', views.vault_edit, name='vault_edit'),
    path('delete/<int:pk>/', views.vault_delete, name='vault_delete'),
    path('password_strength_api/', views.password_strength_api, name='password_strength_api'),
    path('encryption_demo/', views.encryption_demo, name='encryption_demo'),
    path('password_cracker_simulator/', views.password_cracker_simulator, name='password_cracker_simulator'),
    path('password_strength_game/', views.password_strength_game, name='password_strength_game'),
    path('steg_upload/<int:entry_id>/', views.steg_image_upload, name='steg_upload'),
    path('toggle_invisible_ink/', views.invisible_ink_toggle, name='toggle_invisible_ink'),
    path('educational_labels/', views.educational_labels, name='educational_labels'),
    path('caesar_rotator/', views.caesar_rotator_view, name='caesar_rotator'),
    path('browser_addon/', views.browser_addon_info, name='browser_addon'),
    path('api/get_username/', views.get_username, name='get_username'),
    path('api/get_password/<int:entry_id>/', views.get_password, name='get_password'),
    path('download_extension/', views.download_extension, name='download_extension'),
    path('api/login/', views.api_login, name='api_login'),
    path('api/password_search/', views.password_search_api, name='password_search_api'),
]