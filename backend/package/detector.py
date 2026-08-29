from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import numpy as np
from sklearn.ensemble import IsolationForest

failed_logins_by_ip = defaultdict(deque)
s3_reads_by_ip = defaultdict(deque)
region_by_user = {}

model = IsolationForest(contamination=0.08, random_state=42)

baseline_seed = np.array([
    [1, 0, 0, 1],
    [2, 0, 0, 1],
    [1, 1, 0, 1],
    [3, 0, 0, 2],
    [2, 0, 1, 1],
    [1, 0, 0, 2],
    [2, 0, 0, 2],
    [3, 1, 0, 2],
], dtype=float)

model.fit(baseline_seed)


def parse_time(ts: str):
    if not ts:
        return datetime.now(timezone.utc)
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def push_window(store, key, now, seconds=300):
    store[key].append(now)
    cutoff = now - timedelta(seconds=seconds)
    while store[key] and store[key][0] < cutoff:
        store[key].popleft()
    return len(store[key])


def normalize_event(raw: dict):
    if "detail" in raw and isinstance(raw["detail"], dict):
        d = raw["detail"]
        return {
            "timestamp": d.get("eventTime") or raw.get("time"),
            "event_name": d.get("eventName"),
            "event_source": d.get("eventSource"),
            "source_ip": d.get("sourceIPAddress", "unknown"),
            "region": d.get("awsRegion") or raw.get("region", "unknown"),
            "user_arn": ((d.get("userIdentity") or {}).get("arn")) or "unknown",
            "user_type": ((d.get("userIdentity") or {}).get("type")) or "unknown",
            "error_code": d.get("errorCode"),
            "raw": raw
        }

    return {
        "timestamp": raw.get("eventTime"),
        "event_name": raw.get("eventName"),
        "event_source": raw.get("eventSource"),
        "source_ip": raw.get("sourceIPAddress", "unknown"),
        "region": raw.get("awsRegion", "unknown"),
        "user_arn": ((raw.get("userIdentity") or {}).get("arn")) or "unknown",
        "user_type": ((raw.get("userIdentity") or {}).get("type")) or "unknown",
        "error_code": raw.get("errorCode"),
        "raw": raw
    }


def detect_threats(event: dict):
    alerts = []
    now = parse_time(event["timestamp"])
    event_name = event.get("event_name") or "UnknownEvent"
    event_source = event.get("event_source") or "unknown"
    source_ip = event.get("source_ip") or "unknown"
    region = event.get("region") or "unknown"
    user_arn = event.get("user_arn") or "unknown"
    error_code = event.get("error_code")

    if event_name == "ConsoleLogin" and error_code == "FailedAuthentication":
        count = push_window(failed_logins_by_ip, source_ip, now, 300)
        if count >= 5:
            alerts.append({
                "timestamp": now.isoformat(),
                "source_ip": source_ip,
                "attack_type": "Brute Force Login Attempt",
                "severity": "High",
                "description": f"{count} failed ConsoleLogin attempts from the same IP within 5 minutes.",
                "mitigation": "Enable MFA, block the IP, and review IAM sign-in activity."
            })

    sensitive_iam = {
        "CreateAccessKey",
        "DeleteTrail",
        "StopLogging",
        "PutUserPolicy",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion"
    }
    if event_name in sensitive_iam:
        alerts.append({
            "timestamp": now.isoformat(),
            "source_ip": source_ip,
            "attack_type": "Suspicious IAM Change",
            "severity": "Critical",
            "description": f"Sensitive IAM or audit-related API call detected: {event_name}.",
            "mitigation": "Validate the actor, revert unauthorized changes, and rotate credentials if needed."
        })

    if event_source == "s3.amazonaws.com" and event_name in {"GetObject", "ListObjectsV2", "ListBuckets"}:
        count = push_window(s3_reads_by_ip, source_ip, now, 300)
        if count >= 20:
            alerts.append({
                "timestamp": now.isoformat(),
                "source_ip": source_ip,
                "attack_type": "Possible Data Exfiltration",
                "severity": "Critical",
                "description": f"High-volume S3 read pattern detected from {source_ip}.",
                "mitigation": "Review bucket access, suspend suspicious sessions, and inspect accessed objects."
            })

    if user_arn != "unknown":
        previous_region = region_by_user.get(user_arn)
        if previous_region and previous_region != region:
            alerts.append({
                "timestamp": now.isoformat(),
                "source_ip": source_ip,
                "attack_type": "Anomalous Access Pattern",
                "severity": "Medium",
                "description": f"User accessed from a new region: previous={previous_region}, current={region}.",
                "mitigation": "Confirm whether this region change is expected and review recent session activity."
            })
        region_by_user[user_arn] = region

    features = np.array([[
        len(failed_logins_by_ip[source_ip]),
        1 if event_name in sensitive_iam else 0,
        1 if event_source == "s3.amazonaws.com" else 0,
        2 if region != "unknown" else 0
    ]], dtype=float)

    if model.predict(features)[0] == -1:
        alerts.append({
            "timestamp": now.isoformat(),
            "source_ip": source_ip,
            "attack_type": "ML Anomaly Detected",
            "severity": "Medium",
            "description": f"Isolation Forest marked {event_name} as anomalous.",
            "mitigation": "Correlate with CloudTrail history, IAM context, and GuardDuty findings."
        })

    return alerts