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

