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


@login_required(login_url='login')
def index(request):
    template_name='core/index.html'
    context = {

    }
    return render(request, template_name, context)



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
            else:
                messages.error(request, 'Your account is not active please check your email')
                return render(request, 'auth/login.html')
        else:
            messages.error(request, 'Invalid credentials, Please try again')
            return render(request, 'auth/login.html')

    
        messages.error(request, 'Please fill all fields')
        return render(request, 'auth/login.html')


class LogoutView(View):
    def post(self, request):
        auth.logout(request)
        messages.info(request, 'You have been successfully logged out')
        return redirect('login')


def passwordReset(request):
    template_name='auth/password-reset.html'
    context = {
        
    }
    return render(request, template_name, context)

def newPassword(request):
    template_name='auth/new-password.html'
    context = {
        
    }
    return render(request, template_name, context)