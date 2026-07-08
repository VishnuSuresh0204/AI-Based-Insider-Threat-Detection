
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .models import *
from datetime import datetime
from django.utils import timezone
from django.http import JsonResponse
 
 
# Helper function to check if user is logged in
def require_login(request, redirect_url="/login"):
    if "lid" not in request.session:
        messages.error(request, "Please log in to access this page")
        return redirect(redirect_url)
    return None
 
 
def require_admin(request, redirect_url="/login"):
    chk = require_login(request, redirect_url)
    if chk:
        return chk
    l = Login.objects.get(id=request.session["lid"])
    if l.userType != "admin":
        messages.error(request, "Access denied")
        return redirect(redirect_url)
    return None
 
 
def index(request):
    logout(request)
    return render(request, "index.html")
 
 
def login_view(request):
    if request.method == "POST":
        u = request.POST.get("username")
        p = request.POST.get("password")
        user = authenticate(username=u, password=p)
        if user:
            if user.userType == "admin":
                login(request, user)
                request.session["lid"] = user.id
                return redirect("/admin_home")
            elif user.userType == "employee":
                e = EmployeeProfile.objects.get(loginid=user)
                if e.status == "active":
                    login(request, user)
                    request.session["lid"] = user.id
                    return redirect("/employee_home")
                else:
                    messages.error(request, f"Access denied. Account status: {e.status}")
                    return redirect("/login")
        else:
            messages.error(request, "Invalid username or password")
            return redirect("/login")
    return render(request, "login.html")
 
 
def signout(request):
    logout(request)
    return redirect("/")
 
 
# ================= REGISTRATION =================
 
def register_employee(request):
    if request.method == "POST":
        u = request.POST.get("username")
        p = request.POST.get("password")
        n = request.POST.get("name")
        e = request.POST.get("email")
        ph = request.POST.get("phone")
        dept = request.POST.get("department")
        desig = request.POST.get("designation")
        emp_id = request.POST.get("employee_id")
        pic = request.FILES.get("profile_pic")
 
        if Login.objects.filter(username=u).exists():
            messages.error(request, "Username already exists")
            return redirect("/register_employee")
 
        l = Login.objects.create_user(username=u, password=p, userType="employee", viewPass=p)
 
        EmployeeProfile.objects.create(
            loginid=l, name=n, email=e, phone=ph, department=dept,
            designation=desig, employee_id=emp_id, profile_pic=pic,
            date_joined_org=timezone.now().date()
        )
        messages.success(request, "Registration successful. Wait for admin approval.")
        return redirect("/login")
    return render(request, "employee_register.html")
 
 
# ================= ADMIN VIEWS =================
 
def admin_home(request):
    
    return render(request, "ADMIN/admin_home.html")
 
 
def admin_view_employees(request):
    chk = require_admin(request)
    if chk:
        return chk
    e = EmployeeProfile.objects.all()
    return render(request, "ADMIN/view_employees.html", {"val": e})
 
 
def admin_employee_action(request):
    chk = require_admin(request)
    if chk:
        return chk
    id = request.GET.get("id")
    act = request.GET.get("act")  # block / unblock
    e = EmployeeProfile.objects.get(id=id)
    l = e.loginid
    l.is_active = (act == "unblock")
    l.save()
    e.status = "active" if act == "unblock" else "blocked"
    e.save()
    return redirect("/admin_view_employees")
 