"""Optional production alert integrations: Amazon SNS and signed HTTPS webhooks."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List


def _enabled(name: str) -> bool:
    return os.getenv(name, "false").strip().lower() in {"1", "true", "yes", "on"}


def _minimum_severity() -> int:
    return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(os.getenv("ALERT_MIN_SEVERITY", "Medium").title(), 2)


def _eligible(alert: Dict[str, Any]) -> bool:
    return {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}.get(str(alert.get("severity", "Medium")).title(), 2) >= _minimum_severity()


def _sns(alert: Dict[str, Any]) -> Dict[str, Any]:
    topic_arn = os.getenv("SNS_ALERT_TOPIC_ARN", "").strip()
    if not _enabled("SNS_ALERTS_ENABLED"):
        return {"status": "skipped", "reason": "SNS_ALERTS_ENABLED=false"}
    if not topic_arn:
        return {"status": "skipped", "reason": "SNS_ALERT_TOPIC_ARN is not configured"}
    try:
        import boto3
        client = boto3.client("sns", region_name=os.getenv("AWS_REGION") or None)
        response = client.publish(
            TopicArn=topic_arn,
            Subject=f"[CloudSentinel][{alert.get('severity', 'Alert')}] {alert.get('threat_name') or alert.get('attack_type')}",
            Message=json.dumps(alert, default=str, indent=2),
        )
        return {"status": "sent", "message_id": response.get("MessageId")}
    except Exception as exc:
        return {"status": "failed", "reason": str(exc)}


def _webhook(alert: Dict[str, Any]) -> Dict[str, Any]:
    url = os.getenv("ALERT_WEBHOOK_URL", "").strip()
    if not url:
        return {"status": "skipped", "reason": "ALERT_WEBHOOK_URL is not configured"}
    body = json.dumps({"source": "cloudsentinel", "alert": alert}, default=str).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "CloudSentinel/1.0"}
    secret = os.getenv("ALERT_WEBHOOK_SECRET", "")
    if secret:
        headers["X-CloudSentinel-Signature"] = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    try:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=int(os.getenv("ALERT_WEBHOOK_TIMEOUT_SECONDS", "5"))) as response:
            return {"status": "sent", "http_status": response.status}
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        return {"status": "failed", "reason": str(exc)}


def dispatch_integrations(alerts: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Deliver each eligible alert without letting notification failures stop ingestion."""
    results: Dict[str, Dict[str, Any]] = {}
    for alert in alerts:
        alert_id = str(alert.get("alert_id", "unknown-alert"))
        if not _eligible(alert):
            results[alert_id] = {"status": "skipped", "reason": "below minimum severity"}
            continue
        results[alert_id] = {"sns": _sns(alert), "webhook": _webhook(alert)}
    return results
