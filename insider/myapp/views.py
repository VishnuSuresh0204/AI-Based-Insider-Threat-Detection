from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from .models import *
from datetime import datetime
from django.utils import timezone
from django.http import JsonResponse
from . import ml_engine


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
    chk = require_admin(request)
    if chk:
        return chk

    context = {
        "total_alerts": Alert.objects.count(),
        "open_alerts": Alert.objects.filter(status="OPEN").count(),
        "critical_count": RiskAssessment.objects.filter(threat_level="CRITICAL").count(),
        "total_employees": EmployeeProfile.objects.count(),
    }
    return render(request, "ADMIN/admin_home.html", context)


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


def admin_view_activities(request):
    chk = require_admin(request)
    if chk:
        return chk
    a = UserActivity.objects.select_related("risk", "loginid").order_by("-login_time")[:200]
    return render(request, "ADMIN/view_activities.html", {"val": a})


def admin_view_alerts(request):
    chk = require_admin(request)
    if chk:
        return chk
    al = Alert.objects.select_related(
        "risk_assessment", "risk_assessment__activity", "risk_assessment__activity__loginid"
    ).order_by("-created_at")
    return render(request, "ADMIN/view_alerts.html", {"val": al})


def admin_alert_action(request):
    chk = require_admin(request)
    if chk:
        return chk
    id = request.GET.get("id")
    act = request.GET.get("act")  # investigating / resolved / false_positive
    al = Alert.objects.get(id=id)
    al.status = act.upper()
    if act.upper() in ("RESOLVED", "FALSE_POSITIVE"):
        al.resolved_at = timezone.now()
        al.resolved_by = Login.objects.get(id=request.session["lid"])
    al.save()
    messages.success(request, "Alert updated")
    return redirect("/admin_view_alerts")


def admin_retrain_model(request):
    chk = require_admin(request)
    if chk:
        return chk

    normal_activities = UserActivity.objects.filter(risk__is_anomaly=False)
    try:
        ml_engine.train_model(normal_activities)
        messages.success(request, "Model retrained successfully")
    except ValueError as e:
        messages.error(request, str(e))
    return redirect("/admin_home")


# ================= EMPLOYEE VIEWS =================

def employee_home(request):
    chk = require_login(request)
    if chk:
        return chk
    return render(request, "EMPLOYEE/employee_home.html")


def log_activity(request):
    """
    Records a new UserActivity entry for the logged-in employee, then
    immediately runs it through the AI detection engine.
    """
    chk = require_login(request)
    if chk:
        return chk

    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    l = Login.objects.get(id=request.session["lid"])
    now = timezone.now()

    activity = UserActivity.objects.create(
        loginid=l,
        login_time=now,
        ip_address=request.META.get("REMOTE_ADDR", "0.0.0.0"),
        device=request.POST.get("device", ""),
        location=request.POST.get("location", ""),
        files_downloaded=int(request.POST.get("files_downloaded", 0)),
        files_opened=int(request.POST.get("files_opened", 0)),
        usb_connected=request.POST.get("usb_connected") == "true",
        failed_login_attempts=int(request.POST.get("failed_login_attempts", 0)),
        emails_sent=int(request.POST.get("emails_sent", 0)),
        is_weekend=now.weekday() >= 5,
        is_outside_office=request.POST.get("is_outside_office") == "true",
    )

    result = run_detection(activity)

    return JsonResponse({
        "activity_id": activity.id,
        "threat_level": result["threat_level"],
        "risk_score": result["risk_score"],
        "is_anomaly": result["is_anomaly"],
    })


def run_detection(activity):
    """
    Core glue between the AI engine and the database.
    1. Runs ml_engine.evaluate_activity()
    2. Saves a RiskAssessment
    3. Creates an Alert if the threat level warrants it
    """
    try:
        model = ml_engine.load_model()
    except FileNotFoundError:
        model = None  # fall back to rule-based scoring only

    if model is not None:
        result = ml_engine.evaluate_activity(activity, model=model)
    else:
        rule_result = ml_engine.calculate_risk_score(activity)
        result = {"is_anomaly": rule_result["risk_score"] > 60, "anomaly_score": 0.0, **rule_result}

    risk = RiskAssessment.objects.create(
        activity=activity,
        is_anomaly=result["is_anomaly"],
        anomaly_score=result["anomaly_score"],
        risk_score=result["risk_score"],
        threat_level=result["threat_level"],
        reasons=result["reasons"],
    )

    if result["threat_level"] in ("HIGH", "CRITICAL"):
        Alert.objects.create(
            risk_assessment=risk,
            message=(
                f"{activity.loginid.username} flagged {result['threat_level']} "
                f"(score {result['risk_score']}): {', '.join(result['reasons'])}"
            ),
        )

    return result


def my_activity(request):
    """Lets a logged-in employee view their own activity log (transparency)."""
    chk = require_login(request)
    if chk:
        return chk
    l = Login.objects.get(id=request.session["lid"])
    a = UserActivity.objects.filter(loginid=l).order_by("-login_time")[:100]
    return render(request, "EMPLOYEE/my_activity.html", {"val": a})