from __future__ import annotations

from collections import Counter
import os
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from mangum import Mangum
from pymongo.errors import DuplicateKeyError

from database import alerts_collection, database_status, logs_collection
from detector import BEHAVIORAL_ALERT_NAMES, INTERNAL_READ_ONLY_OPERATIONS, detect_threats, enrich_event_with_alerts, is_dashboard_event, normalize_event
from email_service import email_status, send_alert_emails, send_test_email
from notification_service import dispatch_integrations
from security import protect_admin, protect_ingest
from incident_service import build_incidents
from finding_adapter import adapt_eventbridge_findings
from soc_service import case_audit, get_cases, mitre_coverage, service_summary, soc_notifications, ueba_profiles, update_case
from aws_security_hub import get_findings as get_security_hub_findings
from cspm_service import findings_as_alerts, latest_findings as get_cspm_findings, run_scan as run_cspm_scan
from soar_service import approve_action as approve_soar_action, list_actions as get_soar_actions, reject_action as reject_soar_action, request_action as request_soar_action
from aws_organizations import organization_accounts

app = FastAPI(title="CloudSentinel Real AWS Ingestion Backend", version="4.1-email-attempt-fix")

# Vite may expose the local dashboard as either localhost or 127.0.0.1.
# Both are safe local-development origins; deployed environments should set the
# explicit CORS_ALLOW_ORIGINS value in .env.
cors_origins = [origin.strip() for origin in os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:5173,http://localhost:5174,http://127.0.0.1:5173,http://127.0.0.1:5174").split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

memory_logs: List[Dict[str, Any]] = []
memory_alerts: List[Dict[str, Any]] = []


def _insert_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Insert only new alerts and return only alerts newly inserted, so duplicate emails are not sent."""
    if not alerts:
        return []

    inserted: List[Dict[str, Any]] = []

    if alerts_collection is not None:
        for alert in alerts:
            result = alerts_collection.update_one(
                {"alert_id": alert["alert_id"]},
                {"$setOnInsert": alert},
                upsert=True,
            )
            if result.upserted_id:
                inserted.append(alert)
        return inserted

    existing_ids = {a.get("alert_id") for a in memory_alerts}
    for alert in alerts:
        if alert.get("alert_id") not in existing_ids:
            memory_alerts.append(alert)
            inserted.append(alert)
            existing_ids.add(alert.get("alert_id"))
    return inserted


def _update_alert_email_status(email_results: Dict[str, Dict[str, Any]]) -> None:
    """Persist email delivery attempt result on each alert."""
    if not email_results:
        return

    if alerts_collection is not None:
        for alert_id, result in email_results.items():
            alerts_collection.update_one(
                {"alert_id": alert_id},
                {
                    "$set": {
                        "email_status": result.get("status", "unknown"),
                        "email_sent": bool(result.get("sent", False)),
                        "email_reason": result.get("reason") or result.get("error") or "",
                        "email_result": result,
                    }
                },
            )
        return

    for alert in memory_alerts:
        alert_id = str(alert.get("alert_id"))
        if alert_id in email_results:
            result = email_results[alert_id]
            alert["email_status"] = result.get("status", "unknown")
            alert["email_sent"] = bool(result.get("sent", False))
            alert["email_reason"] = result.get("reason") or result.get("error") or ""
            alert["email_result"] = result


def _insert_log(event: Dict[str, Any]) -> bool:
    if logs_collection is not None:
        try:
            result = logs_collection.update_one(
                {"event_id": event["event_id"]},
                {"$setOnInsert": event},
                upsert=True,
            )
            return bool(result.upserted_id)
        except DuplicateKeyError:
            return False

    if not any(item.get("event_id") == event["event_id"] for item in memory_logs):
        memory_logs.append(event)
        return True
    return False


def _behavior_history() -> List[Dict[str, Any]]:
    """Load durable history before inserting the current event for behavioral rules."""
    if logs_collection is not None:
        return list(logs_collection.find({}, {"_id": 0, "raw": 0}))
    return list(memory_logs)


def _dashboard_log(log: Dict[str, Any]) -> Dict[str, Any]:
    """Remove historic false UEBA labels from AWS-native finding records."""
    item = dict(log)
    if item.get("event_name") in {"SecurityHubFinding", "GuardDutyFinding"} and item.get("external_finding"):
        native = [name for name in item.get("threat_types", []) if name not in BEHAVIORAL_ALERT_NAMES]
        if str((item.get("external_finding") or {}).get("severity", "Low")).title() == "Low":
            native = []
        item["threat_types"] = native
        item["threat_detected"] = bool(native)
        item["max_severity"] = (item.get("external_finding") or {}).get("severity") if native else None
    return item


@app.get("/")
def root():
    return {
        "service": "CloudSentinel",
        "message": "Backend is running",
        "ingest_endpoint": "/api/ingest",
        "dashboard_endpoints": ["/api/stats", "/api/logs", "/api/alerts", "/api/threats"],
        "email": email_status(),
    }


@app.get("/health")
def health():
    log_count = logs_collection.count_documents({}) if logs_collection is not None else len(memory_logs)
    alert_count = alerts_collection.count_documents({}) if alerts_collection is not None else len(memory_alerts)
    return {
        "status": "ok",
        "service": "CloudSentinel",
        "database": database_status(),
        "email": email_status(),
        "noise_filter": {"ignore_aws_noise": os.getenv("IGNORE_AWS_NOISE", "true")},
        "ml_alerts": "removed_rule_based_only",
        "counts": {"logs": log_count, "alerts": alert_count},
    }


@app.post("/api/ingest")
async def ingest_event(payload: Dict[str, Any], _: None = Depends(protect_ingest)):
    """Ingest a real CloudTrail event from LookupEvents, EventBridge/Lambda, or direct CloudTrail JSON."""
    event = normalize_event(payload)
    allowed_accounts = {value.strip() for value in os.getenv("ORGANIZATION_ACCOUNT_ALLOWLIST", "").split(",") if value.strip()}
    if allowed_accounts and str(event.get("account_id") or "") not in allowed_accounts:
        raise HTTPException(status_code=403, detail="event account is not in ORGANIZATION_ACCOUNT_ALLOWLIST")

    # Default ON: skip AWS background noise so the dashboard changes mainly when
    # the user performs meaningful AWS actions. To store every event, set
    # IGNORE_AWS_NOISE=false in backend/.env and restart backend.
    ignore_noise = os.getenv("IGNORE_AWS_NOISE", "true").strip().lower() in {"1", "true", "yes", "on"}
    if ignore_noise and event.get("is_noise_event"):
        return {
            "status": "skipped",
            "reason": "noise_event",
            "noise_reason": event.get("noise_reason"),
            "ingested": 0,
            "duplicate": False,
            "event_id": event.get("event_id"),
            "timestamp": event.get("timestamp"),
            "event_name": event.get("event_name"),
            "event_source": event.get("event_source"),
            "source_ip": event.get("source_ip"),
        }

    alerts = detect_threats(event, history=_behavior_history())
    enriched_event = enrich_event_with_alerts(event, alerts)

    inserted_new_log = _insert_log(enriched_event)
    inserted_alerts: List[Dict[str, Any]] = []
    email_results: Dict[str, Dict[str, Any]] = {}
    integration_results: Dict[str, Dict[str, Any]] = {}

    if inserted_new_log:
        inserted_alerts = _insert_alerts(alerts)

        # Important: always record an email attempt result for every newly inserted alert.
        # If email is disabled or misconfigured, status becomes "skipped" or "failed"
        # instead of staying as "not_attempted".
        if inserted_alerts:
            email_results = send_alert_emails(inserted_alerts)
            _update_alert_email_status(email_results)
            integration_results = dispatch_integrations(inserted_alerts)
            for alert in inserted_alerts:
                alert_id = alert.get("alert_id")
                if alert_id in integration_results:
                    result = integration_results[alert_id]
                    if alerts_collection is not None:
                        alerts_collection.update_one({"alert_id": alert_id}, {"$set": {"integration_results": result}})
                    else:
                        alert["integration_results"] = result

    return {
        "status": "success",
        "ingested": 1 if inserted_new_log else 0,
        "duplicate": not inserted_new_log,
        "event_id": enriched_event["event_id"],
        "timestamp": enriched_event.get("timestamp"),
        "event_name": enriched_event.get("event_name"),
        "event_source": enriched_event.get("event_source"),
        "log_type": enriched_event.get("log_type"),
        "activity_detail": enriched_event.get("activity_detail"),
        "resource_name": enriched_event.get("resource_name"),
        "user": enriched_event.get("user_name"),
        "source_ip": enriched_event.get("source_ip"),
        "source_format": enriched_event.get("source_format"),
        "threat_detected": enriched_event.get("threat_detected"),
        "alerts_generated": len(inserted_alerts),
        "alerts": inserted_alerts,
        "email_results": email_results,
        "integration_results": integration_results,
    }


@app.post("/api/ingest/findings")
async def ingest_aws_findings(payload: Dict[str, Any], _: None = Depends(protect_ingest)):
    """Ingest Security Hub or GuardDuty EventBridge findings into the same case queue."""
    events = adapt_eventbridge_findings(payload)
    results = []
    for event in events:
        results.append(await ingest_event(event))
    return {"status": "success", "findings_received": len(events), "results": results}


@app.get("/api/logs")
def get_logs(
    limit: int = Query(default=100, le=1000),
    threats_only: bool = Query(default=False),
    include_noise: bool = Query(default=False),
    search: str = Query(default=""), service: str = Query(default=""), user: str = Query(default=""),
    event_name: str = Query(default=""), region: str = Query(default=""), source_ip: str = Query(default=""), account: str = Query(default=""),
):
    query = {"threat_detected": True} if threats_only else {}
    projection = {"_id": 0, "raw": 0}
    if logs_collection is not None:
        logs = list(logs_collection.find(query, projection).sort("timestamp", -1))
        if not include_noise:
            logs = [log for log in logs if is_dashboard_event(log)]
    else:
        logs = [log for log in memory_logs if not threats_only or log.get("threat_detected")]
        if not include_noise:
            logs = [log for log in logs if is_dashboard_event(log)]
    filters = {"event_source": service, "user_name": user, "event_name": event_name, "region": region, "source_ip": source_ip, "account_id": account}
    for field, value in filters.items():
        if value: logs = [log for log in logs if str(log.get(field, "")).lower() == value.lower()]
    if search:
        needle = search.lower()
        logs = [log for log in logs if needle in " ".join(str(log.get(key, "")) for key in ("event_name", "event_source", "user_name", "resource_name", "activity_detail", "source_ip")).lower()]
    return [_dashboard_log(log) for log in sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)[:limit]]


@app.get("/api/alerts")
def get_alerts(limit: int = Query(default=100, le=1000)):
    if alerts_collection is not None:
        alerts = list(alerts_collection.find({}, {"_id": 0}).sort("timestamp", -1))
    else:
        alerts = sorted(memory_alerts, key=lambda x: x.get("timestamp", ""), reverse=True)
    alerts = [alert for alert in alerts if (str(alert.get("event_source") or ""), str(alert.get("event_name") or "")) not in INTERNAL_READ_ONLY_OPERATIONS]
    # Hide historic false behavioral alerts generated before native AWS findings
    # were excluded from human UEBA rules.
    alerts = [alert for alert in alerts if not (alert.get("event_name") in {"SecurityHubFinding", "GuardDutyFinding"} and (alert.get("threat_name") or alert.get("attack_type")) in BEHAVIORAL_ALERT_NAMES)]
    alerts = [alert for alert in alerts if not (alert.get("event_name") in {"SecurityHubFinding", "GuardDutyFinding"} and str(alert.get("severity", "Low")).title() == "Low")]
    return alerts[:limit]


@app.get("/api/incidents")
def get_incidents(limit: int = Query(default=50, le=500)):
    alerts = get_alerts(limit=1000)
    return get_cases(alerts)[:limit]


@app.post("/api/incidents/{incident_id}/action")
def incident_action(incident_id: str, payload: Dict[str, Any], _: None = Depends(protect_admin)):
    try:
        return update_case(incident_id, payload.get("status", "Open"), payload.get("assigned_analyst", ""), payload.get("comment", ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/incidents/{incident_id}/audit")
def incident_audit(incident_id: str):
    return case_audit(incident_id)


@app.get("/api/mitre")
def get_mitre():
    return mitre_coverage(get_alerts(limit=1000))


@app.get("/api/ueba")
def get_ueba():
    logs = list(logs_collection.find({}, {"_id": 0, "raw": 0})) if logs_collection is not None else memory_logs
    return ueba_profiles(logs)


@app.get("/api/notifications")
def get_notifications(limit: int = Query(default=50, le=500)):
    logs = list(logs_collection.find({}, {"_id": 0, "raw": 0})) if logs_collection is not None else memory_logs
    return soc_notifications(logs, get_alerts(limit=1000), limit)


@app.get("/api/email/status")
def get_email_delivery_status():
    """Expose non-secret mail readiness and recent alert delivery outcomes."""
    return {"configuration": email_status(), "recent_alerts": [{"alert_id": item.get("alert_id"), "timestamp": item.get("timestamp"), "severity": item.get("severity"), "threat_name": item.get("threat_name") or item.get("attack_type"), "email_status": item.get("email_status", "not_attempted"), "email_reason": item.get("email_reason", ""), "email_sent": bool(item.get("email_sent", False))} for item in get_alerts(limit=50)]}


@app.get("/api/services")
def get_services():
    logs = list(logs_collection.find({}, {"_id": 0, "raw": 0})) if logs_collection is not None else memory_logs
    return service_summary(logs, get_alerts(limit=1000))


@app.get("/api/security-hub/findings")
def security_hub_findings(region: str = Query(default=os.getenv("AWS_REGION", "ap-south-1")), page: int = 1, page_size: int = 50, severity: str = "", account: str = "", resource_type: str = "", search: str = ""):
    return get_security_hub_findings(region, page, page_size, severity, account, resource_type, search)


@app.get("/api/organizations/accounts")
def get_organization_accounts():
    """Read-only central account inventory for the multi-account SOC view."""
    return organization_accounts()


@app.get("/api/cspm/findings")
def cspm_findings(severity: str = "", resource_type: str = "", search: str = ""):
    """Return persisted read-only CSPM findings from the most recent authenticated scan."""
    return get_cspm_findings(severity, resource_type, search)


@app.post("/api/cspm/scan")
def cspm_scan(_: None = Depends(protect_admin)):
    """Run a read-only posture scan. Protected because it can enumerate AWS resources."""
    result = run_cspm_scan()
    if result.get("available"):
        posture_alerts = _insert_alerts(findings_as_alerts(result.get("findings", [])))
        result["incident_queue"] = {"alerts_created": len(posture_alerts), "message": "CSPM findings are now available to the shared incident correlation engine."}
    return result


@app.get("/api/soar/actions")
def soar_actions(incident_id: str = "", limit: int = Query(default=100, le=500)):
    """Read the auditable approval and execution state of response actions."""
    return get_soar_actions(incident_id, limit)


@app.post("/api/soar/actions")
def create_soar_action(payload: Dict[str, Any], _: None = Depends(protect_admin)):
    try:
        return request_soar_action(payload.get("incident_id", ""), payload.get("action_type", ""), payload.get("parameters") or {}, payload.get("requested_by", ""), payload.get("reason", ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/soar/actions/{action_id}/approve")
def approve_soar(action_id: str, payload: Dict[str, Any], _: None = Depends(protect_admin)):
    try:
        return approve_soar_action(action_id, payload.get("approved_by", ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/soar/actions/{action_id}/reject")
def reject_soar(action_id: str, payload: Dict[str, Any], _: None = Depends(protect_admin)):
    try:
        return reject_soar_action(action_id, payload.get("rejected_by", ""), payload.get("reason", ""))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/logs/search")
def search_logs(page: int = 1, page_size: int = Query(default=50, le=200), sort_by: str = "timestamp", sort_direction: str = "desc", include_noise: bool = False, search: str = "", service: str = "", user: str = "", event_name: str = "", region: str = "", source_ip: str = ""):
    # Delegates matching to the same backend search used by the activity feed.
    logs = get_logs(limit=1000, include_noise=include_noise, search=search, service=service, user=user, event_name=event_name, region=region, source_ip=source_ip)
    logs = sorted(logs, key=lambda item: str(item.get(sort_by, "")), reverse=sort_direction.lower() != "asc")
    start = max(0, (page - 1) * page_size)
    return {"page": page, "page_size": page_size, "total": len(logs), "items": logs[start:start + page_size]}


@app.get("/api/reports/summary")
def report_summary():
    logs = list(logs_collection.find({}, {"_id": 0, "raw": 0})) if logs_collection is not None else memory_logs
    alerts = get_alerts(limit=1000)
    cases = get_cases(alerts)
    return {"generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(), "executive_summary": get_stats(), "incidents": cases, "mitre": mitre_coverage(alerts), "ueba": ueba_profiles(logs), "services": service_summary(logs, alerts), "cspm": get_cspm_findings(), "alerts": alerts, "logs": logs}


@app.get("/api/threats")
def get_threats(limit: int = Query(default=100, le=1000)):
    return get_alerts(limit=limit)


@app.get("/api/stats")
def get_stats():
    if logs_collection is not None and alerts_collection is not None:
        all_logs = list(logs_collection.find({}, {"_id": 0, "raw": 0}))
        visible_logs = [log for log in all_logs if is_dashboard_event(log)]
        total_logs = len(visible_logs)
        raw_total_logs = len(all_logs)
        total_alerts = len(get_alerts(limit=1000))
        threat_log_count = len([log for log in visible_logs if log.get("threat_detected")])
        severity_counter = Counter(doc.get("severity", "Unknown") for doc in alerts_collection.find({}, {"_id": 0, "severity": 1}))
        attack_counter = Counter(doc.get("attack_type", "Unknown") for doc in alerts_collection.find({}, {"_id": 0, "attack_type": 1}))
        log_type_counter = Counter(doc.get("log_type", "Unknown") for doc in visible_logs)
        event_counter = Counter(doc.get("event_name", "Unknown") for doc in visible_logs)
        source_counter = Counter(doc.get("source_format", "unknown") for doc in visible_logs)
        latest = sorted(visible_logs, key=lambda x: x.get("timestamp", ""), reverse=True)[0] if visible_logs else None
    else:
        visible_logs = [log for log in memory_logs if is_dashboard_event(log)]
        total_logs = len(visible_logs)
        raw_total_logs = len(memory_logs)
        total_alerts = len(memory_alerts)
        threat_log_count = len([log for log in visible_logs if log.get("threat_detected")])
        severity_counter = Counter(alert.get("severity", "Unknown") for alert in memory_alerts)
        attack_counter = Counter(alert.get("attack_type", "Unknown") for alert in memory_alerts)
        log_type_counter = Counter(log.get("log_type", "Unknown") for log in visible_logs)
        event_counter = Counter(log.get("event_name", "Unknown") for log in visible_logs)
        source_counter = Counter(log.get("source_format", "unknown") for log in visible_logs)
        latest = sorted(visible_logs, key=lambda x: x.get("timestamp", ""), reverse=True)[0] if visible_logs else None

    return {
        "total_logs": total_logs,
        "raw_total_logs": raw_total_logs,
        "total_alerts": total_alerts,
        "open_incidents": len(build_incidents(get_alerts(limit=1000))),
        "threat_log_count": threat_log_count,
        "severity_stats": dict(severity_counter),
        "attack_type_stats": dict(attack_counter),
        "log_type_stats": dict(log_type_counter),
        "event_name_stats": dict(event_counter.most_common(10)),
        "source_format_stats": dict(source_counter),
        "latest_event_time": latest.get("timestamp") if latest else None,
        "database": database_status(),
        "email": email_status(),
    }


@app.post("/api/test-email")
def test_email():
    return send_test_email()


@app.post("/api/dev/resend-alert-emails")
def resend_alert_emails(limit: int = Query(default=20, le=100), _: None = Depends(protect_admin)):
    """Development helper: resend emails for recent alerts that were not sent."""
    if alerts_collection is not None:
        alerts = list(
            alerts_collection.find(
                {"email_status": {"$ne": "sent"}},
                {"_id": 0},
            ).sort("timestamp", -1).limit(limit)
        )
    else:
        alerts = [a for a in sorted(memory_alerts, key=lambda x: x.get("timestamp", ""), reverse=True) if a.get("email_status") != "sent"][:limit]

    results = send_alert_emails(alerts)
    _update_alert_email_status(results)
    return {"attempted": len(alerts), "results": results, "email": email_status()}


@app.delete("/api/dev/clear")
def clear_dev_data(_: None = Depends(protect_admin)):
    """Development-only helper. Do not expose publicly on the internet."""
    if logs_collection is not None:
        logs_collection.delete_many({})
        alerts_collection.delete_many({})
    memory_logs.clear()
    memory_alerts.clear()
    return {"status": "cleared"}


handler = Mangum(app, lifespan="off")
