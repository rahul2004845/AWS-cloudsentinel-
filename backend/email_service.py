from __future__ import annotations

import os
import hashlib
import json
import sqlite3
import smtplib
import ssl
import traceback
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Dict, List

from database import SQLITE_PATH

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

SEVERITY_RANK = {"Info": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def _env_bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def email_status() -> Dict[str, Any]:
    password = os.getenv("EMAIL_PASSWORD", "").strip()
    enabled = _env_bool("EMAIL_ALERTS_ENABLED")
    missing = []
    if enabled:
        for key in ["EMAIL_USERNAME", "EMAIL_PASSWORD", "EMAIL_TO"]:
            if not os.getenv(key, "").strip():
                missing.append(key)

    return {
        "enabled": enabled,
        "smtp_host": os.getenv("EMAIL_SMTP_HOST", "smtp.gmail.com"),
        "smtp_port": _env_int("EMAIL_SMTP_PORT", 465),
        "username": os.getenv("EMAIL_USERNAME", ""),
        "username_configured": bool(os.getenv("EMAIL_USERNAME", "").strip()),
        "password_configured": bool(password),
        "password_length": len(password),
        "has_password_spaces": " " in password,
        "to": os.getenv("EMAIL_TO", ""),
        "recipients_configured": bool(os.getenv("EMAIL_TO", "").strip()),
        "min_severity": os.getenv("ALERT_MIN_SEVERITY", "Medium"),
        "timeout_seconds": _env_int("EMAIL_TIMEOUT_SECONDS", 5),
        "cooldown_seconds": _env_int("EMAIL_ALERT_COOLDOWN_SECONDS", 900),
        "ready": enabled and not missing,
        "missing": missing,
    }


def _severity_value(sev: str) -> int:
    return SEVERITY_RANK.get(str(sev or "Medium").strip().title(), 2)


def _should_send(alert: Dict[str, Any]) -> tuple[bool, str]:
    st = email_status()
    if not st["enabled"]:
        return False, "EMAIL_ALERTS_ENABLED=false"
    if st["missing"]:
        return False, "missing email config: " + ", ".join(st["missing"])
    if st["has_password_spaces"]:
        return False, "EMAIL_PASSWORD contains spaces; Gmail app password must be pasted without spaces"

    min_sev = os.getenv("ALERT_MIN_SEVERITY", "Medium").strip().title()
    alert_sev = str(alert.get("severity", "Medium")).strip().title()
    if _severity_value(alert_sev) < _severity_value(min_sev):
        return False, f"alert severity {alert_sev} below ALERT_MIN_SEVERITY={min_sev}"
    return True, "allowed"


def _init_delivery_store() -> None:
    with sqlite3.connect(str(SQLITE_PATH)) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS email_delivery_dedupe (
            fingerprint TEXT PRIMARY KEY, last_sent_at TEXT NOT NULL, alert_id TEXT NOT NULL)""")


def _fingerprint(alert: Dict[str, Any]) -> str:
    # A new CloudTrail event can create a new alert id for the same repeated
    # condition. Fingerprint the security meaning rather than the event id.
    body = {
        "threat": alert.get("threat_name") or alert.get("attack_type"),
        "actor": alert.get("user_arn") or alert.get("user_name"),
        "resource": alert.get("affected_resource") or alert.get("resource_name"),
        "source": alert.get("event_source"),
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()


def _delivery_allowed(alert: Dict[str, Any]) -> tuple[bool, str, str]:
    if alert.get("event_name") == "TestEmail":
        return True, "test delivery", "test-email"
    cooldown = max(0, _env_int("EMAIL_ALERT_COOLDOWN_SECONDS", 900))
    fingerprint = _fingerprint(alert)
    if cooldown == 0:
        return True, "cooldown disabled", fingerprint
    _init_delivery_store()
    with sqlite3.connect(str(SQLITE_PATH)) as conn:
        row = conn.execute("SELECT last_sent_at FROM email_delivery_dedupe WHERE fingerprint=?", (fingerprint,)).fetchone()
    if row:
        try:
            last_sent = datetime.fromisoformat(row[0])
            if last_sent.tzinfo is None: last_sent = last_sent.replace(tzinfo=timezone.utc)
            remaining = int((last_sent + timedelta(seconds=cooldown) - datetime.now(timezone.utc)).total_seconds())
            if remaining > 0:
                return False, f"duplicate email suppressed; retry in {remaining}s", fingerprint
        except ValueError:
            pass
    return True, "cooldown clear", fingerprint


def _record_delivery(fingerprint: str, alert_id: str) -> None:
    if fingerprint == "test-email": return
    _init_delivery_store()
    with sqlite3.connect(str(SQLITE_PATH)) as conn:
        conn.execute("INSERT INTO email_delivery_dedupe(fingerprint,last_sent_at,alert_id) VALUES(?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET last_sent_at=excluded.last_sent_at,alert_id=excluded.alert_id", (fingerprint, datetime.now(timezone.utc).isoformat(), alert_id))


def _clean(value: Any, default: str = "-") -> str:
    if value is None or value == "":
        return default
    return str(value)


def _format_alert_body(alert: Dict[str, Any]) -> str:
    return f"""
CloudSentinel Threat Alert

Threat Name : {_clean(alert.get('threat_name') or alert.get('attack_type'))}
Severity    : {_clean(alert.get('severity'))}
Attack Stage: {_clean(alert.get('attack_stage'))}
Time        : {_clean(alert.get('timestamp_ist') or alert.get('timestamp'))}
Account     : {_clean(alert.get('account_id'))}
Region      : {_clean(alert.get('region'))}

Event       : {_clean(alert.get('event_name'))}
Source      : {_clean(alert.get('event_source'))}
Log Type    : {_clean(alert.get('log_type'))}
Status      : {_clean(alert.get('activity_status'))}
Resource    : {_clean(alert.get('affected_resource') or alert.get('resource_name'))}

User        : {_clean(alert.get('user_name'))}
User ARN    : {_clean(alert.get('user_arn'))}
Source IP   : {_clean(alert.get('source_ip'))}

What Happened:
{_clean(alert.get('what_happened') or alert.get('description'))}

Activity Detail:
{_clean(alert.get('activity_detail'))}

What May Happen Next:
{_clean(alert.get('future_impact'))}

Recommended Action:
{_clean(alert.get('recommended_action') or alert.get('mitigation'))}

Alert ID:
{_clean(alert.get('alert_id'))}
""".strip()


def send_alert_email(alert: Dict[str, Any]) -> Dict[str, Any]:
    allowed, reason = _should_send(alert)
    alert_id = str(alert.get("alert_id", "unknown-alert"))
    if not allowed:
        return {"sent": False, "status": "skipped", "reason": reason, "alert_id": alert_id}
    delivery_allowed, delivery_reason, fingerprint = _delivery_allowed(alert)
    if not delivery_allowed:
        return {"sent": False, "status": "skipped", "reason": delivery_reason, "alert_id": alert_id}

    smtp_host = os.getenv("EMAIL_SMTP_HOST", "smtp.gmail.com")
    smtp_port = _env_int("EMAIL_SMTP_PORT", 465)
    username = os.getenv("EMAIL_USERNAME", "").strip()
    password = os.getenv("EMAIL_PASSWORD", "").strip()
    email_to = os.getenv("EMAIL_TO", "").strip()
    email_from = os.getenv("EMAIL_FROM", username).strip() or username
    timeout = _env_int("EMAIL_TIMEOUT_SECONDS", 5)

    subject = f"[CloudSentinel][{alert.get('severity', 'Alert')}] {alert.get('threat_name') or alert.get('attack_type') or 'Threat Alert'}"

    msg = EmailMessage()
    msg["From"] = email_from
    msg["To"] = email_to
    msg["Subject"] = subject
    msg.set_content(_format_alert_body(alert))

    try:
        if smtp_port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=timeout) as server:
                server.login(username, password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=timeout) as server:
                server.ehlo()
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                server.login(username, password)
                server.send_message(msg)

        _record_delivery(fingerprint, alert_id)
        return {"sent": True, "status": "sent", "reason": "delivered", "alert_id": alert_id, "to": email_to, "subject": subject}
    except Exception as exc:
        return {"sent": False, "status": "failed", "reason": str(exc), "error": str(exc), "alert_id": alert_id, "traceback": traceback.format_exc()}


def send_alert_emails(alerts: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Send emails for a list of alerts and return {alert_id: result}."""
    results: Dict[str, Dict[str, Any]] = {}
    if not alerts:
        return results
    for alert in alerts:
        alert_id = str(alert.get("alert_id", "unknown-alert"))
        results[alert_id] = send_alert_email(alert)
    return results


def send_test_email() -> Dict[str, Any]:
    test_alert = {
        "alert_id": "test-email-alert",
        "timestamp": "now",
        "attack_type": "CloudSentinel Test Alert",
        "threat_name": "CloudSentinel Test Alert",
        "attack_stage": "Email Delivery Test",
        "severity": os.getenv("ALERT_MIN_SEVERITY", "Medium"),
        "account_id": "test-account",
        "region": "test-region",
        "event_name": "TestEmail",
        "event_source": "cloudsentinel.local",
        "log_type": "Email Test",
        "activity_status": "Success",
        "resource_name": "test-resource",
        "user_name": "test-user",
        "user_arn": "test-user-arn",
        "source_ip": "127.0.0.1",
        "description": "This is a CloudSentinel Gmail alert test.",
        "what_happened": "CloudSentinel generated a test alert to verify SMTP email delivery.",
        "future_impact": "No security impact. This confirms whether future real alerts can be emailed.",
        "recommended_action": "No action required. This is a test email.",
        "affected_resource": "test-resource",
        "activity_detail": "Testing SMTP email delivery from CloudSentinel backend.",
        "mitigation": "No action required. This is a test email.",
    }
    return send_alert_email(test_alert)


# Compatibility aliases.
send_email_alert = send_alert_email
send_threat_email = send_alert_email
send_test_alert_email = send_test_email
get_email_health = email_status
