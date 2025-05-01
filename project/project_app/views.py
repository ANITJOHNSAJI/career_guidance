from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.conf import settings
import random
from datetime import datetime, timedelta
from .models import *
from django.urls import reverse
from django.contrib.auth.decorators import login_required

# Create your views here.
def index(request):
    return render(request, 'index.html')

def adminhome(request):
    return render(request,'adminhome.html')

def add(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        maindescription = request.POST.get('maindescription')
        qualification = request.POST.get('qualification')
        subject = request.POST.get('subject')
        interested = request.POST.get('interested')

        qualification_obj = Qualification.objects.get(name=qualification)
        subject_obj = Subject.objects.get(name=subject)
        
        course = Course(
            title=title,
            description=description,
            maindescription=maindescription,
            qualification=qualification_obj,
            subject=subject_obj,
            interested=interested
        )
        course.save()
        
        return redirect('course_list')  # After saving, redirect to another page (e.g., course list)
    else:
        qualifications = Qualification.objects.all()
        subjects = Subject.objects.all()
    return render(request, 'add.html', {'qualifications': qualifications, 'subjects': subjects})

def userlist(request):
    return render(request,'userlist.html')

def profile_view(request):
    """View to display user profile with addresses"""

    addresses = Address.objects.filter(user=request.user)
    
    context = {
        'addresses': addresses,
        'email': request.user.email, 
    }
    return render(request, 'profile.html', context)

@login_required
def add_address(request):
    """View to add a new address without using Django forms"""
    if request.method == 'POST':
        name = request.POST.get('name', '')
        address = request.POST.get('address', '')
        phone = request.POST.get('phone', '')
        
        # Basic validation
        errors = {}
        if not name:
            errors['name'] = 'Name is required.'
        if not address:
            errors['address'] = 'Address is required.'
        if not phone:
            errors['phone'] = 'Phone number is required.'
        
        if not errors:
            # Create new address
            Address.objects.create(
                user=request.user,
                name=name,
                address=address,
                phone=phone
            )
            messages.success(request, 'Address added successfully!')
            return redirect('profile')
        else:
           
            return render(request, 'address.html', {
                'errors': errors,
                'name': name,
                'address': address,
                'phone': phone,
                'action': 'Add'
            })
    
    return render(request, 'address.html', {'action': 'Add'})

@login_required
def edit_address(request, address_id):
    """View to edit an existing address without using Django forms"""
    # Get address or return 404 if not found
    address_obj = get_object_or_404(Address, id=address_id, user=request.user)
    
    if request.method == 'POST':
        name = request.POST.get('name', '')
        address = request.POST.get('address', '')
        phone = request.POST.get('phone', '')
        
        # Basic validation
        errors = {}
        if not name:
            errors['name'] = 'Name is required.'
        if not address:
            errors['address'] = 'Address is required.'
        if not phone:
            errors['phone'] = 'Phone number is required.'
        
        if not errors:
            # Update address
            address_obj.name = name
            address_obj.address = address
            address_obj.phone = phone
            address_obj.save()
            messages.success(request, 'Address updated successfully!')
            return redirect('profile')
        else:
 
            return render(request, 'address.html', {
                'errors': errors,
                'name': name,
                'address': address,
                'phone': phone,
                'action': 'Edit'
            })
    
   
    return render(request, 'address.html', {
        'name': address_obj.name,
        'address': address_obj.address,
        'phone': address_obj.phone,
        'action': 'Edit'
    })

@login_required
def delete_address(request, address_id):
    """View to delete an address"""
    address = get_object_or_404(Address, id=address_id, user=request.user)
    
    if request.method == 'POST':
        address.delete()
        messages.success(request, 'Address deleted successfully!')
        return redirect('profile')
    
    return render(request, 'confirm_delete.html', {'address': address})
@login_required
def edit_email(request):
    """View to edit user's email"""
    user = request.user
    
    if request.method == 'POST':
        email = request.POST.get('email', '')
        
        # Basic validation
        errors = {}
        if not email:
            errors['email'] = 'Email is required.'
        elif '@' not in email:
            errors['email'] = 'Please enter a valid email address.'
            
        if not errors:
            # Update email
            user.email = email
            user.save()
            messages.success(request, 'Email updated successfully!')
            return redirect('profile')
        else:
            # If there are errors, pass them to the template
            return render(request, 'email.html', {
                'errors': errors,
                'email': email
            })
    
    
    return render(request, 'email.html', {
        'email': user.email
    })

@login_required
def edit_username(request):
    """View to edit user's username"""
    user = request.user
    
    if request.method == 'POST':
        username = request.POST.get('username', '')
        
        # Basic validation
        errors = {}
        if not username:
            errors['username'] = 'Username is required.'
        elif len(username) < 4:
            errors['username'] = 'Username should be at least 4 characters long.'
        elif User.objects.filter(username=username).exists():
            errors['username'] = 'This username is already taken.'
            
        if not errors:
            # Update username
            user.username = username
            user.save()
            messages.success(request, 'Username updated successfully!')
            return redirect('profile')
        else:
            # If there are errors, pass them to the template
            return render(request, 'username.html', {
                'errors': errors,
                'username': username
            })
    
    # Pre-fill form with existing username
    return render(request, 'username.html', {
        'username': user.username
    }) 


def usersignup(request):
    if request.method == "POST":
        email = request.POST.get('email')
        username = request.POST.get('username')
        password = request.POST.get('password')
        confirmpassword = request.POST.get('confpassword') 
        
        if not username or not email or not password or not confirmpassword:
            messages.error(request, 'All fields are required.')
        elif confirmpassword != password:
            messages.error(request, "Passwords do not match.")
        elif User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
        elif User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
        else:
            User.objects.create_user(username=username, email=email, password=password)
            messages.success(request, "Account created successfully!")
            return redirect('userlogin') 

    return render(request, "register.html")

def userform(request):
    return render(request, 'userform.html')

def userlogin(request):
    if request.user.is_authenticated:  # Instead of checking session directly
        return redirect('index')  

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            if user.is_superuser:
                return redirect('adminhome')  # Check that the 'firstpage' URL exists
            return redirect('index')
        else:
            messages.error(request, "Invalid credentials.")

    return render(request, 'userlogin.html')

def logoutuser(request):
    logout(request)
    request.session.flush()
    return redirect('userlogin')


def verifyotp(request):
    if request.method == "POST":
        otp = request.POST.get('otp')
        otp1 = request.session.get('otp')
        otp_time_str = request.session.get('otp_time')

        if otp_time_str:
            otp_time = datetime.fromisoformat(otp_time_str)
            otp_expiry_time = otp_time + timedelta(minutes=5)
            if datetime.now() > otp_expiry_time:
                messages.error(request, 'OTP has expired. Please request a new one.')
                del request.session['otp']
                del request.session['otp_time']
                return redirect('verifyotp')  # Allow user to request a new OTP

        if otp == otp1:
            del request.session['otp']
            del request.session['otp_time']
            return redirect('passwordreset')
        else:
            messages.error(request, 'Invalid OTP. Please try again.')

    otp = ''.join(random.choices('123456789', k=6))
    request.session['otp'] = otp
    request.session['otp_time'] = datetime.now().isoformat()

    message = f'Your email verification code is: {otp}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [request.session.get('email')]
    send_mail('Email Verification', message, email_from, recipient_list)

    return render(request, "otp.html")



def getusername(request):
    if request.method == "POST":
        username = request.POST.get('username')
        try:
            user = User.objects.get(username=username)
            request.session['email'] = user.email
            return redirect('verifyotp')
        except User.DoesNotExist:
            messages.error(request, "Username does not exist.")
            return redirect('getusername')

    return render(request, 'getusername.html')


def passwordreset(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        confirmpassword = request.POST.get('confpassword')

        if confirmpassword != password:
            messages.error(request, "Passwords do not match.")
        else:
            email = request.session.get('email')
            try:
                user = User.objects.get(email=email)
                user.set_password(password)
                user.save()
                del request.session['email']
                messages.success(request, "Your password has been reset successfully.")

                user = authenticate(username=user.username, password=password)
                if user is not None:
                    login(request, user)

                return redirect('userlogin') 
            except User.DoesNotExist:
                messages.error(request, "No user found with that email address.")
                return redirect('getusername') 

    return render(request, "passwordreset.html")





