from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import numpy as np
from sklearn.ensemble import IsolationForest

failed_logins_by_ip = defaultdict(deque)
api_calls_by_ip = defaultdict(deque)
region_by_user = {}
model = IsolationForest(contamination=0.08, random_state=42)

baseline_seed = np.array([
    [1, 0, 1],
    [2, 0, 1],
    [1, 1, 1],
    [3, 0, 1],
    [2, 1, 1],
    [1, 0, 2],
    [2, 0, 2],
    [3, 1, 2],
], dtype=float)

model.fit(baseline_seed)


def parse_time(ts: str):
    if not ts:
        return datetime.now(timezone.utc)
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _push_window(store, key, now, seconds=300):
    store[key].append(now)
    limit = now - timedelta(seconds=seconds)
    while store[key] and store[key][0] < limit:
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
    event_name = event["event_name"] or "UnknownEvent"
    source_ip = event["source_ip"] or "unknown"
    region = event["region"] or "unknown"
    user_arn = event["user_arn"] or "unknown"
    error_code = event["error_code"]

    if event_name == "ConsoleLogin" and error_code == "FailedAuthentication":
        count = _push_window(failed_logins_by_ip, source_ip, now, 300)
        if count >= 5:
            alerts.append({
                "timestamp": now.isoformat(),
                "source_ip": source_ip,
                "attack_type": "Brute Force Login Attempt",
                "severity": "High",
                "description": f"{count} failed ConsoleLogin attempts from the same IP within 5 minutes.",
                "mitigation": "Enable MFA, block the IP, and review IAM sign-in activity."
            })

    suspicious_iam = {
        "CreateAccessKey",
        "DeleteTrail",
        "StopLogging",
        "PutUserPolicy",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion"
    }
    if event_name in suspicious_iam:
        alerts.append({
            "timestamp": now.isoformat(),
            "source_ip": source_ip,
            "attack_type": "Suspicious IAM Change",
            "severity": "Critical",
            "description": f"Sensitive IAM or audit configuration action detected: {event_name}.",
            "mitigation": "Validate the actor, revert unauthorized changes, and rotate credentials if necessary."
        })

    exfil_actions = {"GetObject", "ListBuckets", "ListObjectsV2", "GetBucketLocation"}
    if event_name in exfil_actions and event["event_source"] == "s3.amazonaws.com":
        count = _push_window(api_calls_by_ip, source_ip, now, 300)
        if count >= 20:
            alerts.append({
                "timestamp": now.isoformat(),
                "source_ip": source_ip,
                "attack_type": "Possible Data Exfiltration",
                "severity": "Critical",
                "description": f"High-volume S3 access pattern detected from {source_ip}.",
                "mitigation": "Review bucket access, revoke suspicious sessions, and inspect accessed objects."
            })

    if user_arn != "unknown":
        old_region = region_by_user.get(user_arn)
        if old_region and old_region != region:
            alerts.append({
                "timestamp": now.isoformat(),
                "source_ip": source_ip,
                "attack_type": "Anomalous Access Pattern",
                "severity": "Medium",
                "description": f"User accessed AWS from a new region: previous={old_region}, current={region}.",
                "mitigation": "Verify whether this region change is expected and inspect recent API actions."
            })
        region_by_user[user_arn] = region

    feature_vector = np.array([[
        len(failed_logins_by_ip[source_ip]),
        1 if event_name in suspicious_iam else 0,
        2 if region != "unknown" else 0
    ]], dtype=float)

    pred = model.predict(feature_vector)[0]
    if pred == -1:
        alerts.append({
            "timestamp": now.isoformat(),
            "source_ip": source_ip,
            "attack_type": "ML Anomaly Detected",
            "severity": "Medium",
            "description": f"Isolation Forest flagged the event {event_name} as anomalous.",
            "mitigation": "Correlate with CloudTrail history, IAM context, and GuardDuty findings."
        })

    return alerts