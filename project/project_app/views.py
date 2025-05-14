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
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, HttpResponse
from openpyxl import Workbook
from io import BytesIO

def adminhome(request):
    careers = Career.objects.all()
    return render(request, 'adminhome.html', {'careers': careers})

def add_qualification_subjects(request):
    if request.method == 'POST':
        qualification_name = request.POST.get('qualification').strip()
        if qualification_name:
            qualification, created = Qualification.objects.get_or_create(name=qualification_name)
            added_subjects = []
            for i in range(1, 6):
                subject_name = request.POST.get(f'subject{i}')
                if subject_name and subject_name.strip():
                    subject_name_clean = subject_name.strip()
                    if not Subject.objects.filter(name=subject_name_clean, qualification=qualification).exists():
                        Subject.objects.create(name=subject_name_clean, qualification=qualification)
                        added_subjects.append(subject_name_clean)
            if created or added_subjects:
                messages.success(request, "Qualification and subjects added successfully.")
            else:
                messages.info(request, "No new subjects were added.")
        else:
            messages.error(request, "Qualification name is required.")
    qualifications = Qualification.objects.all()
    return render(request, 'add_qualification.html', {'qualifications': qualifications})

@login_required
def edit_qualification(request, pk):
    qualification = get_object_or_404(Qualification, pk=pk)
    if request.method == 'POST':
        qualification.name = request.POST.get('qualification').strip()
        qualification.save()
        return redirect('add-qualification')
    return render(request, 'edit_qualification.html', {'qualification': qualification})

@login_required
def edit_subject(request, pk):
    subject = get_object_or_404(Subject, pk=pk)
    if request.method == 'POST':
        new_name = request.POST.get('subject_name').strip()
        if new_name:
            subject.name = new_name
            subject.save()
            return redirect('add-qualification')
    return render(request, 'edit_subject.html', {'subject': subject})

@login_required
def delete_qualification(request, pk):
    qualification = get_object_or_404(Qualification, pk=pk)
    qualification.delete()
    return redirect('add-qualification')

@login_required
def delete_subject(request, pk):
    subject = get_object_or_404(Subject, pk=pk)
    subject.delete()
    return redirect('add-qualification')

def add(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        maindescription = request.POST.get('maindescription')
        qualification_id = request.POST.get('qualification')
        subject_id = request.POST.get('subject')
        interested = request.POST.get('interested')
        try:
            qualification_obj = Qualification.objects.get(id=qualification_id)
            subject_obj = Subject.objects.get(id=subject_id)
            career = Career(
                title=title,
                description=description,
                maindescription=maindescription,
                qualification=qualification_obj,
                subject=subject_obj,
                interested=interested
            )
            career.save()
            messages.success(request, "Career added successfully.")
            return redirect('adminhome')
        except Qualification.DoesNotExist:
            messages.error(request, "Selected qualification does not exist.")
        except Subject.DoesNotExist:
            messages.error(request, "Selected subject does not exist.")
        except Exception as e:
            messages.error(request, f"An unexpected error occurred: {e}")
    qualifications = Qualification.objects.all()
    subjects = Subject.objects.all()
    return render(request, 'add.html', {'qualifications': qualifications, 'subjects': subjects})

def edit(request, id):
    career = get_object_or_404(Career, id=id)
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        maindescription = request.POST.get('maindescription')
        qualification_id = request.POST.get('qualification')
        subject_id = request.POST.get('subject')
        interested = request.POST.get('interested')
        qualification_obj = Qualification.objects.get(id=qualification_id)
        subject_obj = Subject.objects.get(id=subject_id)
        career.title = title
        career.description = description
        career.maindescription = maindescription
        career.qualification = qualification_obj
        career.subject = subject_obj
        career.interested = interested
        career.save()
        return redirect('adminhome')
    qualifications = Qualification.objects.all()
    subjects = Subject.objects.all()
    return render(request, 'edit.html', {
        'career': career,
        'qualifications': qualifications,
        'subjects': subjects
    })

def delete(request, id):
    career = get_object_or_404(Career, id=id)
    career.delete()
    return redirect('adminhome')

def get_subjects(request, qualification_id):
    subjects = Subject.objects.filter(qualification_id=qualification_id)
    data = {'subjects': [{'id': s.id, 'name': s.name} for s in subjects]}
    return JsonResponse(data)

@login_required
def userlist(request):
    # Fetch all users except superusers, prefetch related data
    users = User.objects.filter(is_superuser=False).prefetch_related('address_set', 'usercareerfilter')
    return render(request, 'userlist.html', {'users': users})

@login_required
def download_all_users_excel(request):
    wb = Workbook()
    ws = wb.active
    ws.title = "All_Users_Details"
    headers = ['Username', 'Email', 'Phone Number', 'Address', 'Qualification', 'Subject', 'Interested In', 'Additional Details']
    ws.append(headers)

    # Fetch all users except superusers, prefetch related data
    users = User.objects.filter(is_superuser=False).prefetch_related('address_set', 'usercareerfilter')
    for user in users:
        # Get the first address or None
        address = user.address_set.first()
        user_career_filter = getattr(user, 'usercareerfilter', None)
        ws.append([
            user.username,
            user.email,
            address.phone if address else 'Not specified',
            address.address if address else 'Not specified',
            user_career_filter.qualification.name if user_career_filter and user_career_filter.qualification else 'Not specified',
            user_career_filter.subject.name if user_career_filter and user_career_filter.subject else 'Not specified',
            user_career_filter.interested if user_career_filter else 'Not specified',
            user_career_filter.details if user_career_filter else 'Not specified'
        ])

    output = BytesIO()
    wb.save(output)
    output.seek(0)
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        content=output.getvalue(),
    )
    response['Content-Disposition'] = 'attachment; filename="all_users_details.xlsx"'
    return response
def message_list(request):
    messages = ContactMessage.objects.all().order_by('-submitted_at')
    return render(request, 'message.html', {'messages': messages})

@login_required
def download_all_messages_excel(request):
    wb = Workbook()
    ws = wb.active
    ws.title = "All_Messages_Details"
    headers = ['Name', 'Email', 'Message', 'Submitted At']
    ws.append(headers)

    messages = ContactMessage.objects.all().order_by('-submitted_at')
    for msg in messages:
        ws.append([
            msg.name,
            msg.email,
            msg.message,
            msg.submitted_at.strftime('%Y-%m-%d %H:%M'),  # Format datetime for Excel
        ])

    output = BytesIO()
    wb.save(output)
    output.seek(0)
    response = HttpResponse(
        content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        content=output.getvalue(),
    )
    response['Content-Disposition'] = 'attachment; filename="all_messages_details.xlsx"'
    return response

@login_required
def userform(request):
    if request.method == 'POST':
        qualification_id = request.POST.get('qualification')
        subject_id = request.POST.get('subject')
        interested = request.POST.get('interested')
        details = request.POST.get('details')
        qualification = Qualification.objects.get(id=qualification_id)
        subject = Subject.objects.get(id=subject_id)
        user_career_filter, created = UserCareerFilter.objects.update_or_create(
            user=request.user,
            defaults={
                'qualification': qualification,
                'subject': subject,
                'interested': interested,
                'details': details,
            }
        )
        return redirect('index')
    qualifications = Qualification.objects.all()
    return render(request, 'userform.html', {'qualifications': qualifications})

def index(request):
    filtered_careers = []
    user_filter = None
    if request.user.is_authenticated:
        try:
            user_filter = UserCareerFilter.objects.get(user=request.user)
            careers = Career.objects.filter(
                qualification=user_filter.qualification,
                subject=user_filter.subject,
                interested=user_filter.interested
            )
            try:
                everyone_qualification = Qualification.objects.get(name__iexact="everyone")
                if user_filter.interested == "Job":
                    job_subject = Subject.objects.get(name__iexact="Job")
                    filtered_careers = Career.objects.filter(
                        qualification=everyone_qualification,
                        subject=job_subject
                    )
                elif user_filter.interested == "Study":
                    study_subject = Subject.objects.get(name__iexact="Study")
                    filtered_careers = Career.objects.filter(
                        qualification=everyone_qualification,
                        subject=study_subject
                    )
            except (Qualification.DoesNotExist, Subject.DoesNotExist):
                messages.error(request, "Default qualifications or subjects not found.")
        except UserCareerFilter.DoesNotExist:
            return redirect('userform')
    else:
        careers = Career.objects.all()
    return render(request, "index.html", {
        "careers": careers,
        "filtered_careers": filtered_careers,
        "user_career_filter": user_filter,
    })

@login_required(login_url='userlogin')
def details(request, product_id):
    career = get_object_or_404(Career, pk=product_id)
    return render(request, 'details.html', {'career': career})

@login_required
def profile_view(request):
    user_career_filter = UserCareerFilter.objects.filter(user=request.user).first()
    addresses = Address.objects.filter(user=request.user)
    context = {
        'addresses': addresses,
        'email': request.user.email,
        'user_career_filter': user_career_filter,
    }
    return render(request, 'profile.html', context)

@login_required
def add_address(request):
    if request.method == 'POST':
        name = request.POST.get('name', '')
        address = request.POST.get('address', '')
        phone = request.POST.get('phone', '')
        errors = {}
        if not name:
            errors['name'] = 'Name is required.'
        if not address:
            errors['address'] = 'Address is required.'
        if not phone:
            errors['phone'] = 'Phone number is required.'
        if not errors:
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
    address_obj = get_object_or_404(Address, id=address_id, user=request.user)
    if request.method == 'POST':
        name = request.POST.get('name', '')
        address = request.POST.get('address', '')
        phone = request.POST.get('phone', '')
        errors = {}
        if not name:
            errors['name'] = 'Name is required.'
        if not address:
            errors['address'] = 'Address is required.'
        if not phone:
            errors['phone'] = 'Phone number is required.'
        if not errors:
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
    address = get_object_or_404(Address, id=address_id, user=request.user)
    if request.method == 'POST':
        address.delete()
        messages.success(request, 'Address deleted successfully!')
        return redirect('profile')
    return render(request, 'confirm_delete.html', {'address': address})

@login_required
def edit_email(request):
    user = request.user
    if request.method == 'POST':
        email = request.POST.get('email', '')
        errors = {}
        if not email:
            errors['email'] = 'Email is required.'
        elif '@' not in email:
            errors['email'] = 'Please enter a valid email address.'
        if not errors:
            user.email = email
            user.save()
            messages.success(request, 'Email updated successfully!')
            return redirect('profile')
        else:
            return render(request, 'email.html', {'errors': errors, 'email': email})
    return render(request, 'email.html', {'email': user.email})

@login_required
def edit_username(request):
    user = request.user
    if request.method == 'POST':
        username = request.POST.get('username', '')
        errors = {}
        if not username:
            errors['username'] = 'Username is required.'
        elif len(username) < 4:
            errors['username'] = 'Username should be at least 4 characters long.'
        elif User.objects.filter(username=username).exists():
            errors['username'] = 'This username is already taken.'
        if not errors:
            user.username = username
            user.save()
            messages.success(request, 'Username updated successfully!')
            return redirect('profile')
        else:
            return render(request, 'username.html', {'errors': errors, 'username': username})
    return render(request, 'username.html', {'username': user.username})

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

def userlogin(request):
    if request.user.is_authenticated:
        return redirect('index')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            if user.is_superuser:
                return redirect('adminhome')
            try:
                UserCareerFilter.objects.get(user=user)
                return redirect('index')
            except UserCareerFilter.DoesNotExist:
                return redirect('userform')
        else:
            messages.error(request, "Invalid credentials.")
    return render(request, 'userlogin.html')

def contact(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')
        ContactMessage.objects.create(name=name, email=email, message=message)
        messages.success(request, 'Your message has been sent and saved successfully!')
        return redirect('contact')
    return render(request, 'contact.html')

def about(request):
    return render(request, 'about.html')

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
                return redirect('verifyotp')
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

