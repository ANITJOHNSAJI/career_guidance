from django.contrib import admin
from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
from project_app import views

urlpatterns = [
    path('userlogin', views.userlogin,name='userlogin'),
    path('signup',views.usersignup,name='usersignup'),
    path('',views.index,name='index'),
    path('forgotpassword',views.getusername,name='forgotpassword'),
    path('verifyotp',views.verifyotp,name='verifyotp'),
    path('passwordreset',views.passwordreset,name='passwordreset'),
    path('logout/', views.logoutuser, name="logout"),
    path('adminhome/', views.adminhome, name='adminhome'),
    path('add/', views.add, name='add'),
    path('userform/', views.userform, name='userform'),
    path('userlist/',views.userlist,name='userlist')
  
]
