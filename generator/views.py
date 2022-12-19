import secrets
import string
import base64
import os
import hashlib

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.urls import reverse

from .models import StorePassword, GeneralPassword

def create_password(request):

    if request.method == 'GET':
        password = ''

    if request.method == 'POST':
        alphabet = []
        if request.POST.get('uppercaseletters', 0) == '1':
            alphabet += list(string.ascii_uppercase)
        if request.POST.get('lowercaseletters', 0) == '1':
            alphabet += list(string.ascii_lowercase)
        if request.POST.get('digits', 0) == '1':
            alphabet += list(string.digits)
        if request.POST.get('symbols', 0) == '1':
            alphabet += list(string.punctuation)

        length = int(request.POST.get('length'))
        if length < 8 or length > 64:
            password = ''
        else:
            password = ''.join(secrets.choice(alphabet) for i in range(length))

    return render(request, 'home.html', context={'data': password})

@login_required
def personal_account(request):

    if request.method == 'GET':
        if request.META.get('HTTP_REFERER') == request.build_absolute_uri(reverse('account')):
            queryset = StorePassword.objects.filter(user=request.user)
            for object in queryset:
                object.password = '**********'

            return render(request, 'youraccount.html', {'queryset': queryset})

        elif request.META.get('HTTP_REFERER') != request.build_absolute_uri(reverse('type_master')):

            return redirect('home')

        else:
            queryset = StorePassword.objects.filter(user=request.user)
            for object in queryset:
                object.password = '**********'
            salt = GeneralPassword.objects.get(user=request.user).salt
            key = GeneralPassword.objects.get(user=request.user).key

            return render(request, 'youraccount.html', {'queryset': queryset})

    if request.method == 'POST':
        if request.META.get('HTTP_REFERER') != request.build_absolute_uri(reverse('account')):
            return redirect('home')
        else:
            salt = GeneralPassword.objects.get(user=request.user).salt
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
            main_password = request.POST.get('add_mainpassword')
            main_password = bytes(main_password, 'utf-8')

            key = base64.urlsafe_b64encode(kdf.derive(main_password))
            f = Fernet(key)

            if request.POST.get('add_website') == '' and request.POST.get('add_username') == '' and request.POST.get('add_password') == '':
                queryset = StorePassword.objects.filter(user=request.user)
                for object in queryset:
                    object.password = f.decrypt(object.password).decode('utf-8')

                return render(request, 'youraccount.html', {'queryset': queryset})

            if request.POST.get('add_website') != '' and request.POST.get('add_username') != '' and request.POST.get('add_password') != '':
                password = request.POST.get('add_password')
                password = bytes(password, 'utf-8')
                encrypted_password = f.encrypt(password)

                StorePassword.objects.create(user=request.user, website=request.POST.get('add_website'), username=request.POST.get('add_username'), password=encrypted_password)

                return redirect('account')

            else:
                return redirect('account')

@login_required
def create_master_password(request):

    if request.method == 'GET': 
        if request.META.get('HTTP_REFERER') != request.build_absolute_uri(reverse('home')):
            return redirect('home')
        else:
            if GeneralPassword.objects.filter(user=request.user).exists():
                return redirect('type_master')

    if request.method == 'POST':
        if request.META.get('HTTP_REFERER') != request.build_absolute_uri(reverse('master')):
            return redirect('home')
        else:
            if request.POST.get('password1') == request.POST.get('password2'):
                salt = os.urandom(32)
                key = hashlib.pbkdf2_hmac('sha256', request.POST.get('password1').encode('utf-8'), salt, 480000)

                object = GeneralPassword.objects.create(user=request.user, salt=salt, key=key)
                return redirect('home')
            else:
                messages.add_message(request, messages.WARNING, "Passwords don't match")

    return render(request, 'masterpassword.html')

@login_required
def type_master_password(request):

    if request.method == 'GET':
        if request.META.get('HTTP_REFERER') != request.build_absolute_uri(reverse('home')):
            return redirect('home')
        else:
            pass

    if request.method == 'POST':
        if request.META.get('HTTP_REFERER') != request.build_absolute_uri(reverse('type_master')):
            return redirect('home')
        else:
            master_password = request.POST.get('account_mainpassword')
            salt = GeneralPassword.objects.get(user=request.user).salt
            key = GeneralPassword.objects.get(user=request.user).key
        
            new_key = hashlib.pbkdf2_hmac('sha256', master_password.encode('utf-8'), salt, 480000)

            if new_key == key:
                return redirect('account')
            else:
                messages.add_message(request, messages.WARNING, 'Wrong password')
        
    return render(request, 'type_masterpassword.html')