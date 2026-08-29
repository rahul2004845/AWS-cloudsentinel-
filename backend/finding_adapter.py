"""Adapters for AWS-native security findings delivered through EventBridge."""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List


def _severity(value: Any) -> str:
    text = str(value or "Medium").upper()
    if text in {"CRITICAL", "HIGH"}: return text.title()
    if text in {"MEDIUM", "MODERATE"}: return "Medium"
    return "Low"


def _id(value: Any) -> str:
    return hashlib.sha256(str(value).encode()).hexdigest()


def adapt_eventbridge_findings(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert Security Hub or GuardDuty EventBridge events to CloudSentinel input."""
    source = str(payload.get("source") or "")
    detail = payload.get("detail") or {}
    timestamp = payload.get("time") or detail.get("updatedAt") or detail.get("updated_at")
    findings = detail.get("findings") if source == "aws.securityhub" else [detail]
    events = []
    for finding in findings or []:
        resource = finding.get("Resources", [{}])[0] if isinstance(finding.get("Resources"), list) else finding.get("resource") or {}
        resource_name = resource.get("Id") or resource.get("id") or finding.get("resource", {}).get("resourceType") or "-"
        finding_type = finding.get("Types", [None])[0] if isinstance(finding.get("Types"), list) else finding.get("type")
        title = finding.get("Title") or finding.get("title") or finding_type or "AWS security finding"
        finding_id = finding.get("Id") or finding.get("id") or _id(finding)
        events.append({
            "eventID": f"finding-{_id(finding_id)}",
            "eventTime": timestamp,
            "eventName": "SecurityHubFinding" if source == "aws.securityhub" else "GuardDutyFinding",
            "eventSource": "securityhub.amazonaws.com" if source == "aws.securityhub" else "guardduty.amazonaws.com",
            "awsRegion": finding.get("Region") or finding.get("region") or payload.get("region"),
            "recipientAccountId": finding.get("AwsAccountId") or finding.get("accountId") or payload.get("account"),
            "userIdentity": {"type": "AWSService", "arn": source or "aws.security"},
            "external_finding": {"provider": "Security Hub" if source == "aws.securityhub" else "GuardDuty", "finding_id": finding_id, "title": title, "description": finding.get("Description") or finding.get("description") or title, "severity": _severity((finding.get("Severity") or {}).get("Label") if isinstance(finding.get("Severity"), dict) else finding.get("severity")), "resource": resource_name},
        })
    return events
