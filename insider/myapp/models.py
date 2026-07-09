
from django.db import models
from django.contrib.auth.models import AbstractUser
 
 
# ---------------- LOGIN ---------------- #
 
class Login(AbstractUser):
    userType = models.CharField(
        max_length=50
    )  # admin / employee
 
    viewPass = models.CharField(
        max_length=100,
        null=True,
        blank=True
    )
 
    def __str__(self):
        return self.username
 
 
# ---------------- EMPLOYEE PROFILE ---------------- #
 
class EmployeeProfile(models.Model):
    loginid = models.ForeignKey(
        Login,
        on_delete=models.CASCADE
    )
 
    name = models.CharField(max_length=200)
 
    email = models.EmailField()
 
    phone = models.CharField(max_length=20)
 
    department = models.CharField(
        max_length=100,
        null=True,
        blank=True
    )
 
    designation = models.CharField(
        max_length=100,
        null=True,
        blank=True
    )
 
    employee_id = models.CharField(
        max_length=50,
        null=True,
        blank=True
    )
 
    date_joined_org = models.DateField(
        null=True,
        blank=True
    )
 
    profile_pic = models.ImageField(
        upload_to="employee_profiles",
        null=True,
        blank=True
    )
 
    status = models.CharField(
        max_length=20,
        default="active"  # active / suspended / blocked
    )
 
    def __str__(self):
        return self.name
 
 
# ---------------- USER ACTIVITY ---------------- #
 
class UserActivity(models.Model):
    """
    One row = one snapshot of an employee's activity (per login session,
    or per day). This is the raw data the AI model learns from.
    """
    loginid = models.ForeignKey(
        Login,
        on_delete=models.CASCADE,
        related_name="activities"
    )
 
    login_time = models.DateTimeField()
 
    logout_time = models.DateTimeField(
        null=True,
        blank=True
    )
 
    ip_address = models.GenericIPAddressField()
 
    device = models.CharField(
        max_length=100,
        null=True,
        blank=True
    )
 
    location = models.CharField(
        max_length=100,
        null=True,
        blank=True
    )
 
    files_downloaded = models.IntegerField(default=0)
 
    files_opened = models.IntegerField(default=0)
 
    usb_connected = models.BooleanField(default=False)
 
    failed_login_attempts = models.IntegerField(default=0)
 
    emails_sent = models.IntegerField(default=0)
 
    is_weekend = models.BooleanField(default=False)
 
    is_outside_office = models.BooleanField(default=False)
 
    created_at = models.DateTimeField(auto_now_add=True)
 
    class Meta:
        ordering = ["-login_time"]
 
    def __str__(self):
        return f"{self.loginid.username} @ {self.login_time}"
 
 
# ---------------- RISK ASSESSMENT ---------------- #
 
class RiskAssessment(models.Model):
    """
    Stores the AI model's verdict for a given UserActivity record.
    """
    THREAT_LEVELS = [
        ("SAFE", "Safe"),
        ("MEDIUM", "Medium"),
        ("HIGH", "High"),
        ("CRITICAL", "Critical"),
    ]
 
    activity = models.OneToOneField(
        UserActivity,
        on_delete=models.CASCADE,
        related_name="risk"
    )
 
    is_anomaly = models.BooleanField(default=False)
 
    anomaly_score = models.FloatField(default=0.0)  # raw ML model output
 
    risk_score = models.IntegerField(default=0)  # 0-150+ scale
 
    threat_level = models.CharField(
        max_length=10,
        choices=THREAT_LEVELS,
        default="SAFE"
    )
 
    reasons = models.JSONField(
        default=list,
        blank=True
    )  # e.g. ["Login at 2 AM", "USB connected"]
 
    evaluated_at = models.DateTimeField(auto_now_add=True)
 
    def __str__(self):
        return f"{self.activity.loginid.username} - {self.threat_level} ({self.risk_score})"
 