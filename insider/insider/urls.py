from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
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
    path("admin_view_activities/", views.admin_view_activities),
    path("admin_view_alerts/", views.admin_view_alerts),
    path("admin_alert_action/", views.admin_alert_action),
    path("admin_retrain_model/", views.admin_retrain_model),

    # Employee
    path("employee_home/", views.employee_home),
    path("log_activity/", views.log_activity),
    path("my_activity/", views.my_activity),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)