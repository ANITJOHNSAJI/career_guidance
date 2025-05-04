from django.contrib import admin
from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
from project_app import views

urlpatterns = [
    path('', views.userlogin, name='userlogin'),
    path('signup',views.usersignup,name='usersignup'),
    path('index',views.index,name='index'),
    path('forgotpassword',views.getusername,name='forgotpassword'),
    path('verifyotp',views.verifyotp,name='verifyotp'),
    path('passwordreset',views.passwordreset,name='passwordreset'),
    path('logout/', views.logoutuser, name="logout"),
    path('adminhome/', views.adminhome, name='adminhome'),
    path('userform/', views.userform, name='userform'),
    path('userlist/',views.userlist,name='userlist'),
    path('profile/', views.profile_view, name='profile'),
    path('profile/add-address/', views.add_address, name='add_address'),
    path('profile/edit-address/<int:address_id>/', views.edit_address, name='edit_address'),
    path('profile/delete-address/<int:address_id>/', views.delete_address, name='delete_address'),
    path('profile/edit-email/', views.edit_email, name='edit_email'),
    path('profile/edit-username/', views.edit_username, name='edit_username'),
    path('details/<int:product_id>/', views.details, name='details'),
    path('contact/', views.contact, name='contact'),
    path('about/',views.about,name='about'),
    path('message_list/', views.message_list, name='message_list'),
    path('add-qualification/', views.add_qualification_subjects, name='add-qualification'),
    path('add/', views.add, name='add'),
    path('get-subjects/<int:qualification_id>/', views.get_subjects, name='get_subjects'),


   
  
]
