"""Read live AWS Security Hub findings using the backend's IAM role or profile."""
from __future__ import annotations
import os
from typing import Any, Dict, List
import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError


def _client(region: str):
    profile = os.getenv("AWS_PROFILE")
    session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client("securityhub", region_name=region)


def _severity(finding: Dict[str, Any]) -> str:
    return ((finding.get("Severity") or {}).get("Label") or "INFORMATIONAL").title()


def _normalize(finding: Dict[str, Any]) -> Dict[str, Any]:
    resource = (finding.get("Resources") or [{}])[0]
    remediation = finding.get("Remediation") or {}
    return {
        "finding_id": finding.get("Id"), "product_arn": finding.get("ProductArn"), "title": finding.get("Title"),
        "description": finding.get("Description"), "severity": _severity(finding), "account_id": finding.get("AwsAccountId"),
        "region": finding.get("Region"), "resource": resource.get("Id"), "resource_type": resource.get("Type"),
        "generator": finding.get("GeneratorId"), "workflow_status": (finding.get("Workflow") or {}).get("Status"),
        "compliance_status": (finding.get("Compliance") or {}).get("Status"), "record_state": finding.get("RecordState"),
        "created_at": finding.get("CreatedAt"), "updated_at": finding.get("UpdatedAt"),
        "recommendation": (remediation.get("Recommendation") or {}).get("Text"), "remediation_url": (remediation.get("Recommendation") or {}).get("Url"),
        "raw": finding,
    }


def get_findings(region: str, page: int = 1, page_size: int = 50, severity: str = "", account: str = "", resource_type: str = "", search: str = "") -> Dict[str, Any]:
    if not os.getenv("SECURITY_HUB_ENABLED", "false").lower() in {"1", "true", "yes", "on"}:
        return {"available": False, "reason": "Security Hub integration is disabled. Set SECURITY_HUB_ENABLED=true and configure an AWS IAM role/profile.", "findings": [], "summary": {}}
    try:
        client = _client(region)
        findings: List[Dict[str, Any]] = []
        token = None
        # Security Hub pagination is fetched only up to the requested page to avoid
        # downloading a complete enterprise finding corpus for one UI request.
        for current_page in range(1, page + 1):
            response = client.get_findings(MaxResults=min(100, page_size), NextToken=token) if token else client.get_findings(MaxResults=min(100, page_size))
            if current_page == page: findings = [_normalize(item) for item in response.get("Findings", [])]
            token = response.get("NextToken")
            if not token: break
        def matches(item):
            text = " ".join(str(item.get(k, "")) for k in ("title", "description", "resource", "finding_id")).lower()
            return (not severity or item["severity"].lower() == severity.lower()) and (not account or item["account_id"] == account) and (not resource_type or item["resource_type"] == resource_type) and (not search or search.lower() in text)
        findings = [item for item in findings if matches(item)]
        counts = {level: sum(1 for item in findings if item["severity"].lower() == level.lower()) for level in ("Critical", "High", "Medium", "Low")}
        return {"available": True, "region": region, "page": page, "page_size": page_size, "has_next_page": bool(token), "findings": findings, "summary": {"total_on_page": len(findings), **counts, "active": sum(1 for item in findings if item["record_state"] == "ACTIVE"), "archived": sum(1 for item in findings if item["record_state"] == "ARCHIVED")}}
    except (NoCredentialsError, BotoCoreError, ClientError) as exc:
        return {"available": False, "reason": f"Security Hub is unavailable in {region}: {exc}", "findings": [], "summary": {}}
