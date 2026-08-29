"""Persistence and read models for the SOC console."""
from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List

from database import SQLITE_PATH
from incident_service import build_incidents


def _conn():
    conn = sqlite3.connect(str(SQLITE_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_soc_store() -> None:
    with _conn() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS incident_cases (
            incident_id TEXT PRIMARY KEY, status TEXT NOT NULL, assigned_analyst TEXT,
            comment TEXT, updated_at TEXT NOT NULL)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS incident_audit (
            audit_id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL,
            action TEXT NOT NULL, previous_value TEXT, new_value TEXT, analyst TEXT,
            comment TEXT, occurred_at TEXT NOT NULL)""")


init_soc_store()


def get_cases(alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    incidents = build_incidents(alerts)
    with _conn() as conn:
        states = {row["incident_id"]: dict(row) for row in conn.execute("SELECT * FROM incident_cases")}
    for item in incidents:
        state = states.get(item["incident_id"], {})
        item.update({"status": state.get("status", "Open"), "assigned_analyst": state.get("assigned_analyst", "Unassigned"), "analyst_comment": state.get("comment", "")})
    return incidents


def update_case(incident_id: str, status: str, analyst: str = "", comment: str = "") -> Dict[str, Any]:
    allowed = {"Open", "Acknowledged", "Escalated", "Resolved", "Closed", "False Positive", "Reopened"}
    if status not in allowed:
        raise ValueError(f"invalid status: {status}")
    now = datetime.now(timezone.utc).isoformat()
    with _conn() as conn:
        previous = conn.execute("SELECT status FROM incident_cases WHERE incident_id=?", (incident_id,)).fetchone()
        conn.execute("""INSERT INTO incident_cases(incident_id,status,assigned_analyst,comment,updated_at)
            VALUES(?,?,?,?,?) ON CONFLICT(incident_id) DO UPDATE SET status=excluded.status,
            assigned_analyst=CASE WHEN excluded.assigned_analyst='' THEN incident_cases.assigned_analyst ELSE excluded.assigned_analyst END,
            comment=CASE WHEN excluded.comment='' THEN incident_cases.comment ELSE excluded.comment END, updated_at=excluded.updated_at""",
            (incident_id, status, analyst, comment, now))
        conn.execute("INSERT INTO incident_audit(incident_id,action,previous_value,new_value,analyst,comment,occurred_at) VALUES(?,?,?,?,?,?,?)", (incident_id, "status_change", previous["status"] if previous else "New", status, analyst, comment, now))
    return {"incident_id": incident_id, "status": status, "assigned_analyst": analyst or None, "comment": comment or None, "updated_at": now}


def case_audit(incident_id: str) -> List[Dict[str, Any]]:
    with _conn() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM incident_audit WHERE incident_id=? ORDER BY audit_id DESC", (incident_id,))]


def mitre_coverage(alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    records: Dict[str, Dict[str, Any]] = {}
    for alert in alerts:
        for item in alert.get("mitre_attack", []):
            key = item.get("id")
            if not key: continue
            record = records.setdefault(key, {**item, "detection_count": 0, "related_alert_ids": []})
            record["detection_count"] += 1
            record["related_alert_ids"].append(alert.get("alert_id"))
    return sorted(records.values(), key=lambda item: item["detection_count"], reverse=True)


def ueba_profiles(logs: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    profiles: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for log in logs:
        user = log.get("user_name") or log.get("user_arn") or "unknown"
        if user != "unknown": profiles[str(user)].append(log)
    result = []
    for user, events in profiles.items():
        latest = max(events, key=lambda item: item.get("timestamp", ""))
        ueba = latest.get("ueba") or {}
        result.append({"user": user, "risk_score": ueba.get("score", 0), "baseline_ready": ueba.get("baseline_ready", False), "baseline": ueba.get("baseline", {}), "reasons": ueba.get("reasons", []), "event_count": len(events), "last_activity": latest.get("timestamp")})
    return sorted(result, key=lambda item: item["risk_score"], reverse=True)


def service_summary(logs: Iterable[Dict[str, Any]], alerts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts = Counter(log.get("event_source", "unknown") for log in logs)
    alert_counts = Counter(alert.get("event_source", "unknown") for alert in alerts)
    return [{"service": service, "events": count, "alerts": alert_counts.get(service, 0)} for service, count in counts.most_common()]


def soc_notifications(logs: Iterable[Dict[str, Any]], alerts: Iterable[Dict[str, Any]], limit: int = 50) -> List[Dict[str, Any]]:
    items = []
    for alert in alerts:
        items.append({"id": alert.get("alert_id"), "timestamp": alert.get("timestamp"), "kind": "threat", "severity": alert.get("severity"), "title": alert.get("threat_name") or alert.get("attack_type"), "message": alert.get("what_happened") or alert.get("description")})
    for log in logs:
        if log.get("event_name") == "ConsoleLogin":
            items.append({"id": f"login-{log.get('event_id')}", "timestamp": log.get("timestamp"), "kind": "login", "severity": "High" if log.get("activity_status") == "Failed" or log.get("user_type") == "Root" else "Info", "title": "AWS Console Login", "message": f"{log.get('user_name')} from {log.get('source_ip')} — {log.get('activity_status')}"})
    return sorted(items, key=lambda item: item.get("timestamp") or "", reverse=True)[:limit]
