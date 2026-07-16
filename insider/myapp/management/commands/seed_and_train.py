"""
seed_and_train.py
-----------------
Management command: python manage.py seed_and_train

1. Seeds the database with synthetic "normal" UserActivity rows linked
   to a dedicated system user (username: _ml_seed_user_).
   Skipped automatically if enough normal rows already exist.

2. Trains the Isolation Forest on ALL non-anomalous UserActivity rows
   and saves the model to myapp/isolation_forest_model.pkl.

Usage:
    python manage.py seed_and_train            # seed 50 rows + train
    python manage.py seed_and_train --no-seed  # train on existing data only
    python manage.py seed_and_train --rows 100 # seed 100 rows + train
"""

import random
from datetime import timedelta

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from myapp.models import Login, UserActivity, RiskAssessment
from myapp import ml_engine


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEED_USERNAME = "_ml_seed_user_"
DEVICES = ["Windows-PC", "MacBook", "Linux-WS"]
LOCATIONS = ["HQ", "Branch-A", "Branch-B"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_or_create_seed_user():
    user, _ = Login.objects.get_or_create(
        username=SEED_USERNAME,
        defaults={"userType": "employee", "is_active": False},
    )
    if not user.has_usable_password():
        user.set_unusable_password()
        user.save()
    return user


def _random_normal_activity(seed_user, rng: random.Random):
    """
    Returns an unsaved UserActivity representing completely normal behaviour:
      - Login between 07:00 and 17:59
      - 0-1 failed login attempts
      - 0-25 files downloaded
      - USB not connected, inside office, weekday
    """
    days_ago = rng.randint(1, 90)
    base = timezone.now() - timedelta(days=days_ago)
    # Push to nearest previous weekday if needed
    while base.weekday() >= 5:
        base -= timedelta(days=1)

    login_hour = rng.randint(7, 17)
    login_dt = base.replace(
        hour=login_hour,
        minute=rng.randint(0, 59),
        second=0,
        microsecond=0,
    )
    logout_dt = login_dt + timedelta(hours=rng.randint(4, 10))

    return UserActivity(
        loginid=seed_user,
        login_time=login_dt,
        logout_time=logout_dt,
        ip_address=f"192.168.1.{rng.randint(2, 254)}",
        device=rng.choice(DEVICES),
        location=rng.choice(LOCATIONS),
        files_downloaded=rng.randint(0, 25),
        files_opened=rng.randint(0, 50),
        usb_connected=False,
        failed_login_attempts=rng.randint(0, 1),
        emails_sent=rng.randint(0, 20),
        is_weekend=False,
        is_outside_office=False,
    )


# ---------------------------------------------------------------------------
# Management Command
# ---------------------------------------------------------------------------

class Command(BaseCommand):
    help = (
        "Seed synthetic normal activity rows into the DB, then train and save "
        "the Isolation Forest model (myapp/isolation_forest_model.pkl)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--no-seed",
            action="store_true",
            help="Skip seeding; train on whatever normal data already exists.",
        )
        parser.add_argument(
            "--rows",
            type=int,
            default=50,
            help="Number of synthetic rows to seed (default: 50).",
        )
        parser.add_argument(
            "--contamination",
            type=float,
            default=0.05,
            help="IsolationForest contamination fraction (default: 0.05).",
        )

    # ---------------------------------------------------------------------- #

    def handle(self, *args, **options):
        no_seed      = options["no_seed"]
        target_rows  = options["rows"]
        contamination = options["contamination"]

        # ------------------------------------------------------------------ #
        # Step 1 – Seed synthetic normal data                                 #
        # ------------------------------------------------------------------ #
        if not no_seed:
            # Count rows already confirmed normal OR not yet assessed
            existing_normal = UserActivity.objects.filter(risk__is_anomaly=False).count()
            unassessed      = UserActivity.objects.filter(risk__isnull=True).count()
            total_usable    = existing_normal + unassessed

            if total_usable >= target_rows:
                self.stdout.write(
                    self.style.WARNING(
                        f"Seed skipped — {total_usable} usable rows already present."
                    )
                )
            else:
                needed = target_rows - total_usable
                self.stdout.write(f"Seeding {needed} synthetic normal activity rows...")

                seed_user  = _get_or_create_seed_user()
                rng        = random.Random(42)
                activities = [_random_normal_activity(seed_user, rng) for _ in range(needed)]
                UserActivity.objects.bulk_create(activities)

                # Attach RiskAssessment rows so the queryset filter works
                created_acts = UserActivity.objects.filter(
                    loginid=seed_user, risk__isnull=True
                )
                risk_rows = []
                for act in created_acts:
                    rule = ml_engine.calculate_risk_score(act)
                    risk_rows.append(
                        RiskAssessment(
                            activity=act,
                            is_anomaly=False,
                            anomaly_score=0.0,
                            risk_score=rule["risk_score"],
                            threat_level=rule["threat_level"],
                            reasons=rule["reasons"],
                        )
                    )
                RiskAssessment.objects.bulk_create(risk_rows)
                self.stdout.write(
                    self.style.SUCCESS(f"  [OK] Seeded {needed} rows with risk assessments.")
                )

        # ------------------------------------------------------------------ #
        # Step 2 – Train the model                                            #
        # ------------------------------------------------------------------ #
        self.stdout.write("Training Isolation Forest model...")
        normal_qs = UserActivity.objects.filter(risk__is_anomaly=False)
        count     = normal_qs.count()

        if count < 20:
            raise CommandError(
                f"Only {count} normal records found; need at least 20. "
                "Re-run without --no-seed to auto-seed synthetic data."
            )

        self.stdout.write(f"  Using {count} normal activity records.")
        ml_engine.train_model(normal_qs, contamination=contamination)

        self.stdout.write(
            self.style.SUCCESS(f"  [OK] Model saved -> {ml_engine.MODEL_PATH}")
        )
        self.stdout.write(self.style.SUCCESS("Done! ML engine is now fully active."))
