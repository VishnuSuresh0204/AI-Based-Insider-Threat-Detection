"""
ml_engine.py
------------
The AI brain of the Insider Threat Detection System.

Pipeline:
  1. extract_features()   -> turns a UserActivity row into a numeric vector
  2. train_model()        -> fits an Isolation Forest on "normal" history
  3. predict()             -> flags new activity as normal / anomalous
  4. calculate_risk_score() -> turns flagged behaviour into an explainable score
"""

import os
import joblib
import numpy as np
from datetime import datetime
from sklearn.ensemble import IsolationForest

MODEL_PATH = os.path.join(os.path.dirname(__file__), "isolation_forest_model.pkl")

# Feature order matters everywhere. Keep this list as the single source of truth.
FEATURE_NAMES = [
    "login_hour",
    "failed_login_attempts",
    "files_downloaded",
    "usb_connected",
    "is_outside_office",
    "is_weekend",
]


def extract_features(activity) -> np.ndarray:
    """
    Converts a UserActivity model instance (or any object/dict with the
    same fields) into the numeric feature vector the ML model expects.
    """
    if isinstance(activity, dict):
        login_hour = activity["login_time"].hour
        failed_logins = activity.get("failed_login_attempts", 0)
        downloads = activity.get("files_downloaded", 0)
        usb = int(bool(activity.get("usb_connected", False)))
        outside = int(bool(activity.get("is_outside_office", False)))
        weekend = int(bool(activity.get("is_weekend", False)))
    else:
        login_hour = activity.login_time.hour
        failed_logins = activity.failed_login_attempts
        downloads = activity.files_downloaded
        usb = int(activity.usb_connected)
        outside = int(activity.is_outside_office)
        weekend = int(activity.is_weekend)

    return np.array([[login_hour, failed_logins, downloads, usb, outside, weekend]])


def train_model(activity_queryset, contamination: float = 0.05):
    """
    Trains (or retrains) the Isolation Forest on a set of "mostly normal"
    historical UserActivity rows, then saves it to disk.

    contamination = expected proportion of anomalies in the training data.
    Start low (0.02-0.05) since insider attacks should be rare.
    """
    rows = [extract_features(a)[0] for a in activity_queryset]
    if len(rows) < 20:
        raise ValueError("Need at least ~20 historical activity records to train a useful model.")

    X = np.array(rows)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(X)

    joblib.dump(model, MODEL_PATH)
    return model


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            "No trained model found. Run train_model() first (e.g. via a management command)."
        )
    return joblib.load(MODEL_PATH)


def predict(activity, model=None):
    """
    Returns (is_anomaly: bool, anomaly_score: float).
    IsolationForest.decision_function: lower (more negative) = more abnormal.
    predict(): -1 = anomaly, 1 = normal.
    """
    if model is None:
        model = load_model()

    X = extract_features(activity)
    raw_prediction = model.predict(X)[0]        # -1 or 1
    score = model.decision_function(X)[0]        # continuous anomaly score

    is_anomaly = raw_prediction == -1
    return is_anomaly, float(score)


def calculate_risk_score(activity) -> dict:
    """
    Explainable rule-based risk score, run alongside the ML anomaly flag.
    This is what actually gets shown to the admin, because "anomaly = -1"
    means nothing to a non-technical reviewer, but "Risk Score 120, USB
    used at 2 AM" does.
    """
    reasons = []
    score = 0

    login_hour = activity.login_time.hour if not isinstance(activity, dict) else activity["login_time"].hour
    failed_logins = activity.failed_login_attempts if not isinstance(activity, dict) else activity.get("failed_login_attempts", 0)
    downloads = activity.files_downloaded if not isinstance(activity, dict) else activity.get("files_downloaded", 0)
    usb = activity.usb_connected if not isinstance(activity, dict) else activity.get("usb_connected", False)
    outside = activity.is_outside_office if not isinstance(activity, dict) else activity.get("is_outside_office", False)
    weekend = activity.is_weekend if not isinstance(activity, dict) else activity.get("is_weekend", False)

    if login_hour < 6 or login_hour >= 22:
        score += 20
        reasons.append(f"Login at unusual hour ({login_hour}:00)")

    if failed_logins >= 5:
        score += 30
        reasons.append(f"{failed_logins} failed login attempts")
    elif failed_logins >= 2:
        score += 10
        reasons.append(f"{failed_logins} failed login attempts")

    if downloads >= 100:
        score += 30
        reasons.append(f"{downloads} files downloaded")
    elif downloads >= 40:
        score += 15
        reasons.append(f"{downloads} files downloaded")

    if usb:
        score += 15
        reasons.append("USB device connected")

    if outside:
        score += 25
        reasons.append("Login from outside normal location")

    if weekend:
        score += 10
        reasons.append("Weekend activity")

    if score <= 30:
        level = "SAFE"
    elif score <= 60:
        level = "MEDIUM"
    elif score <= 100:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {"risk_score": score, "threat_level": level, "reasons": reasons}


def evaluate_activity(activity, model=None) -> dict:
    """
    Convenience wrapper used by views.py: runs the ML anomaly check AND
    the explainable risk score together, returns one combined result.
    """
    is_anomaly, anomaly_score = predict(activity, model=model)
    risk = calculate_risk_score(activity)

    return {
        "is_anomaly": is_anomaly,
        "anomaly_score": anomaly_score,
        **risk,
    }
