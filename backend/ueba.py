"""Deterministic, explainable UEBA baseline and deviation scoring; no ML model."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import Any, Dict, Iterable

from detector import parse_time


def score_event(event: Dict[str, Any], history: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    user = str(event.get("user_arn") or "unknown")
    prior = [item for item in history if str(item.get("user_arn") or "unknown") == user and item.get("event_id") != event.get("event_id")]
    if user == "unknown" or len(prior) < 5:
        return {"score": 0, "baseline_ready": False, "reasons": [], "baseline": {"observations": len(prior)}}

    current_time = parse_time(event.get("timestamp"))
    hours = Counter(parse_time(item.get("timestamp")).hour for item in prior)
    regions = Counter(str(item.get("region") or "unknown") for item in prior)
    services = Counter(str(item.get("event_source") or "unknown") for item in prior)
    ips = Counter(str(item.get("source_ip") or "unknown") for item in prior)
    resources = Counter(str(item.get("resource_name") or "-") for item in prior)
    score, reasons = 0, []
    if str(event.get("source_ip") or "unknown") not in ips:
        score += 20; reasons.append("New source IP for this identity (+20)")
    if str(event.get("region") or "unknown") not in regions:
        score += 20; reasons.append("New AWS region for this identity (+20)")
    if current_time.hour not in hours:
        score += 15; reasons.append("Activity outside observed login/activity hours (+15)")
    if str(event.get("event_source") or "unknown") not in services:
        score += 15; reasons.append("Previously unused AWS service (+15)")
    if str(event.get("resource_name") or "-") not in resources and event.get("is_mutating_event"):
        score += 10; reasons.append("New resource targeted by a write action (+10)")
    if event.get("user_type") == "Root":
        score += 30; reasons.append("Root account activity (+30)")
    if event.get("activity_status") == "Failed":
        score += 10; reasons.append("Failed API/authentication activity (+10)")
    if event.get("event_name") in {"DeleteBucket", "TerminateInstances", "StopLogging", "DeleteTrail", "CreateAccessKey", "AttachRolePolicy", "AttachUserPolicy"}:
        score += 25; reasons.append("Sensitive or destructive cloud action (+25)")

    recent = [item for item in prior if parse_time(item.get("timestamp")) >= current_time - timedelta(hours=2)]
    recent_regions = {str(item.get("region") or "unknown") for item in recent}
    if len(recent_regions) > 1 and str(event.get("region") or "unknown") not in recent_regions:
        score += 20; reasons.append("Rapid cross-region activity; investigate possible impossible travel (+20)")
    return {
        "score": min(100, score), "baseline_ready": True, "reasons": reasons,
        "baseline": {"observations": len(prior), "typical_hours_utc": sorted(hours), "normal_regions": list(regions), "frequent_services": [name for name, _ in services.most_common(5)], "common_source_ips": [ip for ip, _ in ips.most_common(5)]},
    }
