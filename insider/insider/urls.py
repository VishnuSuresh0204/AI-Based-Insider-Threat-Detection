from django.contrib import admin
from django.urls import path
from myapp import views
 
urlpatterns = [
    path("", views.index),
    path("login/", views.login_view),
    path("signout/", views.signout),
 
    # Registration
    path("register_employee/", views.register_employee),
 
    # Admin
    path("admin_home/", views.admin_home),
    path("admin_view_employees/", views.admin_view_employees),
    path("admin_employee_action/", views.admin_employee_action),
]