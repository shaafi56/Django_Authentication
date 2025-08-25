from . import views
from django.urls import path

urlpatterns = [
    path("", views.Home, name="home"),
    path("register/", views.RegisterView, name="register"),
    path("login/", views.LoginView, name="login"),
    #path("forgot-password/", views.ForgotPasswordView, name="forgot_password"),
    path('logout/', views.LogoutView, name='logout'),

    path('forgot-password/', views.ForgotPassword, name='forgot_password'),
    path('password-reset-sent/<uuid:reset_id>/', views.PasswordResetSent, name='password_reset_sent'),
    path('reset-password/<uuid:reset_id>/', views.ResetPassword, name='reset_password'),
]