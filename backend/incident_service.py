"""Turn many low-level alerts into small, explainable security incidents."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import timedelta
from typing import Any, Dict, Iterable, List

from detector import parse_time

SEVERITY_SCORE = {"Low": 20, "Medium": 45, "High": 70, "Critical": 90}


def _case_id(alerts: List[Dict[str, Any]]) -> str:
    representative = alerts[0]
    body = {
        "user": representative.get("user_arn") or representative.get("user_name"),
        "ip": representative.get("source_ip"),
        "resource": representative.get("affected_resource") or representative.get("resource_name"),
        "threats": sorted({item.get("threat_name") or item.get("attack_type") for item in alerts}),
    }
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()[:16]


def build_incidents(alerts: Iterable[Dict[str, Any]], window_minutes: int = 30) -> List[Dict[str, Any]]:
    """Group related alerts by actor/IP/resource in a time window.

    This replaces a noisy one-alert-per-event view with cases an analyst can
    investigate. The grouping is deterministic and fully explainable.
    """
    ordered = sorted(alerts, key=lambda item: parse_time(item.get("timestamp")), reverse=True)
    groups: list[List[Dict[str, Any]]] = []
    for alert in ordered:
        actor = alert.get("user_arn") or alert.get("user_name") or "unknown"
        ip = alert.get("source_ip") or "unknown"
        resource = alert.get("affected_resource") or alert.get("resource_name") or "-"
        timestamp = parse_time(alert.get("timestamp"))
        for group in groups:
            first = group[0]
            same_entity = (
                (first.get("user_arn") or first.get("user_name") or "unknown") == actor
                or (first.get("source_ip") or "unknown") == ip
                or (first.get("affected_resource") or first.get("resource_name") or "-") == resource
            )
            if same_entity and abs(parse_time(first.get("timestamp")) - timestamp) <= timedelta(minutes=window_minutes):
                group.append(alert)
                break
        else:
            groups.append([alert])

    incidents = []
    for group in groups:
        severities = [SEVERITY_SCORE.get(str(item.get("severity")), 20) for item in group]
        ueba_score = max((int((item.get("ueba") or {}).get("score", 0)) for item in group), default=0)
        score = min(100, max(max(severities), ueba_score) + min(20, (len(group) - 1) * 5))
        representative = group[0]
        threats = list(dict.fromkeys(item.get("threat_name") or item.get("attack_type") or "Unknown" for item in group))
        actions = list(dict.fromkeys(item.get("recommended_action") or item.get("mitigation") for item in group if item.get("recommended_action") or item.get("mitigation")))
        mitre = list({item["id"]: item for alert in group for item in alert.get("mitre_attack", [])}.values())
        severity = "Critical" if score >= 90 else "High" if score >= 70 else "Medium" if score >= 45 else "Low"
        incidents.append({
            "incident_id": _case_id(group),
            "status": "Open",
            "severity": severity,
            "risk_score": score,
            "first_seen": min(parse_time(item.get("timestamp")) for item in group).isoformat(),
            "last_seen": max(parse_time(item.get("timestamp")) for item in group).isoformat(),
            "actor": representative.get("user_name") or representative.get("user_arn") or "unknown",
            "source_ip": representative.get("source_ip") or "unknown",
            "affected_resource": representative.get("affected_resource") or representative.get("resource_name") or "-",
            "threats": threats,
            "evidence_count": len(group),
            "ueba_score": ueba_score,
            "ueba_reasons": list(dict.fromkeys(reason for item in group for reason in (item.get("ueba") or {}).get("reasons", []))),
            "mitre_attack": mitre,
            "attack_path": [item.get("event_name") for item in sorted(group, key=lambda item: parse_time(item.get("timestamp")))],
            "recommended_actions": actions[:3],
            "business_impact": "Multiple related security signals were correlated into one incident to reduce alert fatigue and prioritize investigation.",
            "evidence": [{"event_name": item.get("event_name"), "timestamp": item.get("timestamp"), "severity": item.get("severity"), "alert_id": item.get("alert_id")} for item in group[:10]],
        })
    return sorted(incidents, key=lambda item: (item["risk_score"], item["last_seen"]), reverse=True)
