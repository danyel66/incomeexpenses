from django.shortcuts import render, redirect
from django.views import View
from django.http import JsonResponse
import json
from django.contrib.auth.models import User
from validate_email import validate_email
from django.contrib import messages
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.template.loader import render_to_string
from .utils import account_activation_token
from django.urls import reverse
from django.contrib import auth
from django.contrib.auth.decorators import login_required
import os
from django.conf import settings
from .models import UserPreference
from django.contrib.auth.tokens import PasswordResetTokenGenerator


def error_404_view(request, exception):
    return render(request, '404.html')


@login_required(login_url='login')
def index(request):
    currency_data = []
    file_path = os.path.join(settings.BASE_DIR, 'currencies.json')

    with open(file_path, 'r') as json_file:
        data = json.load(json_file)
        for k, v in data.items():
            currency_data.append({'name': k, 'value': v})

    exists = UserPreference.objects.filter(user=request.user).exists()
    user_preferences = None
    if exists:
        user_preferences = UserPreference.objects.get(user=request.user)
    if request.method == 'GET':

        return render(request, 'preference/index.html', {'currencies': currency_data,
                                                          'user_preferences': user_preferences})
    else:

        currency = request.POST['currency']
        if exists:
            user_preferences.currency = currency
            user_preferences.save()
        else:
            UserPreference.objects.create(user=request.user, currency=currency)
        messages.success(request, 'Changes saved')
        return render(request, 'preference/index.html', {'currencies': currency_data, 'user_preferences': user_preferences})



class EmailValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        email = data['email']
        if not validate_email(email):
            return JsonResponse({'email_error': 'email is invalid'}, status=400)
        if User.objects.filter(email=email).exists():
            return JsonResponse({'email_error': 'sorry email in use,choose another one'}, status=409)
        return JsonResponse({'email_valid': True})


class UsernameValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        username = data['username']
        if not str(username).isalnum():
            return JsonResponse({'username_error': 'username should only contain alphanumeric characters'}, status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({'username_error': 'sorry username in use,choose another one '}, status=409)
        return JsonResponse({'username_valid': True})


class RegisterView(View):
    def get(self, request):
        context = {

        }
        return render(request, 'auth/register.html', context)

    def post(self, request):

        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']

        context = {
            'fieldValue': request.POST,
        }

        if not User.objects.filter(username=username).exists():
            if not User.objects.filter(email=email).exists():

                if len(password) < 8:
                    messages.error(request, "Password too Short")
                    return render(request, 'auth/register.html', context)

                user = User.objects.create(username=username, email=email)
                user.set_password(password)
                user.save()
                current_site = get_current_site(request)
                email_body = {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': account_activation_token.make_token(user),
                }

                link = reverse('activate', kwargs={
                               'uidb64': email_body['uid'], 'token': email_body['token']})

                email_subject = 'Activate your account'

                activate_url = 'http://'+current_site.domain+link

                email = EmailMessage(
                    email_subject,
                    'Hi '+user.username + ', Please the link below to activate your account \n'+activate_url,
                    'noreply@semycolon.com',
                    [email],
                )
                email.send(fail_silently=False)
                messages.success(request, "Congratulations your account has been created successfully!!")
                return render(request, 'auth/register.html')

        return render(request, 'auth/register.html')


class VerificationView(View):
    def get(self, request, uidb64, token):
        try:
            id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=id)

            if not account_activation_token.check_token(user, token):
                messages.info(request, 'User already activated')
                return redirect('login'+'?message='+'User already activated')

            if user.is_active:
                return redirect('login')
            user.is_active = True
            user.save()

            messages.success(request, 'Account activated successfully')
            return redirect('login')

        except Exception as ex:
            pass

        return redirect('login')


class LoginView(View):
    def get(self, request):

        return render(request, 'auth/login.html')

    def post(self, request):

        username=request.POST['username']
        password=request.POST['password']

        if username and password:
            user=auth.authenticate(username=username, password=password)

            if user:
                if user.is_active:
                    auth.login(request, user)
                    messages.success(request, 'Welcome, '+ user.username + ' you are now logged in')
                    return redirect('index')
            
                messages.error(request, 'Your account is not active please check your email')
                return render(request, 'auth/login.html')
        
            messages.error(request, 'Invalid credentials, Please try again')
            return render(request, 'auth/login.html')

    
        messages.error(request, 'Please fill all fields')
        return render(request, 'auth/login.html')


class LogoutView(View):
    def post(self, request):
        auth.logout(request)
        messages.info(request, 'You have been successfully logged out')
        return redirect('login')


# def expenses(request):
#     template_name='core/add_expenses.html'
#     context = {
        
#     }
#     return render(request, template_name, context)


class PasswordResetView(View):
    def get(self, request):
        return render(request, 'auth/password-reset.html')


    def post(self, request):

        email = request.POST['email']

        context = {
            'values': request.POST,
        }

        if not validate_email(email):
            messages.error(request, 'Invalid Email, please input a valid email')
            return render(request, 'auth/password-reset.html', context)


        current_site = get_current_site(request)

        user = User.objects.filter(email=email)

        if user.exists():
            email_contents = {
            'user': user[0],
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
            'token': PasswordResetTokenGenerator().make_token(user[0]),
        } 

            link = reverse('new-password', kwargs={
                            'uidb64': email_contents['uid'], 'token': email_contents['token']})

            email_subject = 'Password Reset Instruction'

            reset_url = 'http://'+current_site.domain+link

            email = EmailMessage(
                email_subject,
                'Hi Dear, Please the link below to reset your password \n'+reset_url,
                'noreply@semycolon.com',
                [email],
            )
            email.send(fail_silently=False)
            

        messages.success(request, "We have sent an email to reset your pasword")

        

        return render(request, 'auth/password-reset.html')


class NewPasswordView(View):
    def get(self, request, uidb64, token):

        context = {
            'uidb64': uidb64,
            'token': token
        }

        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            
            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.success(request, "Invalid link, Please try again")
                return render(request, 'auth/password-reset.html')

        except Exception as identifier:
            pass

        return render(request, 'auth/new-password.html', context)

    def post(self, request, uidb64, token):

        context = {
            'uidb64': uidb64,
            'token': token
        }

        password = request.POST['password']
        password2 = request.POST['password2']

        if password != password2:
            messages.error(request, "Password field do no match")
            return render(request, 'auth/new-password.html', context)

        if len(password) < 6:
            messages.error(request, "Password too short")
            return render(request, 'auth/new-password.html', context)

        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()

            messages.success(request, "Congratulations your password has been changed successfully!!")
            return redirect('login')


        except Exception as identifier:
            messages.error(request, 'Something went wrong. Please try again')
        
        return render(request, 'auth/new-password.html', context)

