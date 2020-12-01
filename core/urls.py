from django.urls import path
from .views import index, UsernameValidationView, LoginView, RegisterView, newPassword, passwordReset, EmailValidationView, VerificationView, LogoutView
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    path('', index, name='index'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),

    path('password-reset/', passwordReset, name='password-reset'),
    path('new-password/', newPassword, name='new-password'),
    path('register/', RegisterView.as_view(), name='register'),
    path('username-validator', csrf_exempt(UsernameValidationView.as_view()), name='username-validator'),
    path('email-validator', csrf_exempt(EmailValidationView.as_view()), name='email-validator'),
    path('activate/<uidb64>/<token>', VerificationView.as_view(), name='activate'),



]