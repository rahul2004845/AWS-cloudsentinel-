"""Read-only AWS CSPM and exposure-management checks for CloudSentinel.

The scanner deliberately reports only evidence collected from AWS APIs.  It does
not mutate customer resources and permission/API errors are returned separately
from failed controls so that an unavailable check is never shown as a pass.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from database import SQLITE_PATH


def _enabled() -> bool:
    return os.getenv("CSPM_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


def _regions() -> List[str]:
    configured = os.getenv("CSPM_REGIONS", os.getenv("AWS_REGION", "ap-south-1"))
    return list(dict.fromkeys(item.strip() for item in configured.split(",") if item.strip()))


def _session():
    profile = os.getenv("AWS_PROFILE")
    return boto3.Session(profile_name=profile) if profile else boto3.Session()


def _store() -> sqlite3.Connection:
    connection = sqlite3.connect(str(SQLITE_PATH))
    connection.row_factory = sqlite3.Row
    return connection


def init_cspm_store() -> None:
    with _store() as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS cspm_scans (
            scan_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, completed_at TEXT,
            status TEXT NOT NULL, account_id TEXT, regions TEXT, errors TEXT)""")
        connection.execute("""CREATE TABLE IF NOT EXISTS cspm_findings (
            finding_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, severity TEXT NOT NULL,
            resource TEXT, resource_type TEXT, check_id TEXT, observed_at TEXT NOT NULL,
            doc TEXT NOT NULL)""")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_cspm_findings_scan ON cspm_findings(scan_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_cspm_findings_severity ON cspm_findings(severity)")


init_cspm_store()


def _account_id(session) -> str:
    try:
        return session.client("sts").get_caller_identity().get("Account", "unknown")
    except (BotoCoreError, ClientError):
        return "unknown"


def _finding(check_id: str, severity: str, title: str, description: str, resource: str, resource_type: str,
             region: str, evidence: Dict[str, Any], remediation: str, controls: List[str]) -> Dict[str, Any]:
    key = f"{check_id}|{resource}|{region}"
    return {
        "finding_id": "cspm-" + hashlib.sha256(key.encode()).hexdigest()[:20], "source": "CloudSentinel CSPM",
        "check_id": check_id, "severity": severity, "title": title, "description": description,
        "resource": resource, "resource_type": resource_type, "region": region, "evidence": evidence,
        "remediation": remediation, "compliance_controls": controls,
        "exposure": severity in {"Critical", "High"}, "observed_at": datetime.now(timezone.utc).isoformat(),
    }


def _public_cidr(permission: Dict[str, Any]) -> str | None:
    ranges = permission.get("IpRanges", [])
    ipv6 = permission.get("Ipv6Ranges", [])
    for item in ranges:
        if item.get("CidrIp") == "0.0.0.0/0": return "0.0.0.0/0"
    for item in ipv6:
        if item.get("CidrIpv6") == "::/0": return "::/0"
    return None


def _scan_global(session, region: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    findings: List[Dict[str, Any]] = []; errors: List[Dict[str, str]] = []
    try:
        s3 = session.client("s3", region_name=region)
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]; resource = f"arn:aws:s3:::{name}"
            try:
                block = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
                missing = [key for key in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets") if not block.get(key)]
                if missing:
                    findings.append(_finding("S3_PUBLIC_ACCESS_BLOCK", "High", "S3 bucket public-access protection is incomplete",
                        f"Bucket {name} does not enable all account/bucket public-access protections.", resource, "AwsS3Bucket", region,
                        {"missing_settings": missing}, "Enable S3 Block Public Access at account level and confirm the bucket policy has no intentional public exception.", ["CIS AWS 2.1.5", "PCI DSS 7.2", "SOC 2 CC6.1"]))
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "AWS error")
                if code not in {"NoSuchPublicAccessBlockConfiguration", "AccessDenied", "AccessDeniedException"}: errors.append({"check": "S3_PUBLIC_ACCESS_BLOCK", "resource": resource, "error": code})
                elif code == "NoSuchPublicAccessBlockConfiguration":
                    findings.append(_finding("S3_PUBLIC_ACCESS_BLOCK", "High", "S3 bucket has no public-access block configuration", f"Bucket {name} has no bucket-level Public Access Block configuration.", resource, "AwsS3Bucket", region, {"api_error": code}, "Enable S3 Block Public Access and review existing policies/ACLs.", ["CIS AWS 2.1.5", "PCI DSS 7.2", "SOC 2 CC6.1"]))
                else: errors.append({"check": "S3_PUBLIC_ACCESS_BLOCK", "resource": resource, "error": code})
            try:
                s3.get_bucket_encryption(Bucket=name)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "AWS error")
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    findings.append(_finding("S3_DEFAULT_ENCRYPTION", "Medium", "S3 bucket default encryption is not configured", f"Bucket {name} has no default server-side encryption policy.", resource, "AwsS3Bucket", region, {"api_error": code}, "Configure default SSE-S3 or SSE-KMS encryption and verify application compatibility.", ["CIS AWS 2.1.1", "PCI DSS 3.5", "SOC 2 CC6.7"]))
                elif code not in {"AccessDenied", "AccessDeniedException"}: errors.append({"check": "S3_DEFAULT_ENCRYPTION", "resource": resource, "error": code})
    except (BotoCoreError, ClientError) as exc: errors.append({"check": "S3", "resource": "account", "error": str(exc)})
    try:
        iam = session.client("iam", region_name=region)
        summary = iam.get_account_summary().get("SummaryMap", {})
        if not summary.get("AccountMFAEnabled", 0):
            findings.append(_finding("IAM_ROOT_MFA", "Critical", "Root user MFA is not enabled", "The AWS account root user is not protected by MFA.", "root", "AwsIamUser", "global", {"AccountMFAEnabled": 0}, "Enable a hardware or virtual MFA device for the root user and avoid day-to-day root usage.", ["CIS AWS 1.5", "PCI DSS 8.4", "SOC 2 CC6.1"]))
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                if not iam.list_mfa_devices(UserName=username).get("MFADevices", []):
                    findings.append(_finding("IAM_USER_MFA", "Medium", "IAM user has no MFA device", f"IAM user {username} has no registered MFA device.", user.get("Arn", username), "AwsIamUser", "global", {"user": username}, "Require MFA through IAM policy or migrate workforce users to IAM Identity Center.", ["CIS AWS 1.10", "PCI DSS 8.4", "SOC 2 CC6.1"]))
    except (BotoCoreError, ClientError) as exc: errors.append({"check": "IAM", "resource": "account", "error": str(exc)})
    return findings, errors


def _scan_region(session, region: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    findings: List[Dict[str, Any]] = []; errors: List[Dict[str, str]] = []
    try:
        ec2 = session.client("ec2", region_name=region)
        for group in ec2.describe_security_groups().get("SecurityGroups", []):
            for permission in group.get("IpPermissions", []):
                cidr = _public_cidr(permission); ports = [permission.get("FromPort"), permission.get("ToPort")]
                protocol = permission.get("IpProtocol")
                if cidr and (protocol == "-1" or any(port in {22, 3389} for port in ports)):
                    service = "all traffic" if protocol == "-1" else ("SSH" if 22 in ports else "RDP")
                    findings.append(_finding("EC2_PUBLIC_ADMIN_PORT", "High", f"Security group exposes {service} to the internet", f"Security group {group.get('GroupName')} allows {service} from {cidr}.", group.get("GroupId"), "AwsEc2SecurityGroup", region, {"group_name": group.get("GroupName"), "cidr": cidr, "from_port": permission.get("FromPort"), "to_port": permission.get("ToPort"), "protocol": protocol}, "Restrict administrative access to approved VPN/bastion CIDRs or use AWS Systems Manager Session Manager.", ["CIS AWS 5.2", "PCI DSS 1.2", "SOC 2 CC6.6"]))
        if not ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault"):
            findings.append(_finding("EC2_EBS_DEFAULT_ENCRYPTION", "Medium", "EBS default encryption is disabled", "New EBS volumes in this Region are not encrypted by default.", f"account/{region}", "AwsEc2Account", region, {"EbsEncryptionByDefault": False}, "Enable EBS encryption by default and choose an approved KMS key where required.", ["CIS AWS 2.2.1", "PCI DSS 3.5", "SOC 2 CC6.7"]))
    except (BotoCoreError, ClientError) as exc: errors.append({"check": "EC2", "resource": region, "error": str(exc)})
    try:
        trails = session.client("cloudtrail", region_name=region).describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            findings.append(_finding("CLOUDTRAIL_ENABLED", "High", "No CloudTrail trail found in Region", "CloudSentinel could not find a CloudTrail trail in this Region.", f"account/{region}", "AwsCloudTrailTrail", region, {}, "Create a multi-Region organization trail with log-file validation and secure S3 storage.", ["CIS AWS 3.1", "PCI DSS 10.2", "SOC 2 CC7.2"]))
        for trail in trails:
            status = session.client("cloudtrail", region_name=region).get_trail_status(Name=trail["Name"])
            if not status.get("IsLogging"):
                findings.append(_finding("CLOUDTRAIL_LOGGING", "Critical", "CloudTrail trail is not logging", f"Trail {trail['Name']} is configured but not actively logging.", trail.get("TrailARN", trail["Name"]), "AwsCloudTrailTrail", region, {"IsLogging": False}, "Start logging immediately and investigate the stop event before closing the incident.", ["CIS AWS 3.1", "PCI DSS 10.2", "SOC 2 CC7.2"]))
            selectors = session.client("cloudtrail", region_name=region).get_event_selectors(TrailName=trail["Name"])
            basic_s3_data = any(resource.get("Type") == "AWS::S3::Object" for selector in selectors.get("EventSelectors", []) for resource in selector.get("DataResources", []))
            advanced_data = any(any(field.get("Field") == "eventCategory" and "Data" in field.get("Equals", []) for field in selector.get("FieldSelectors", [])) for selector in selectors.get("AdvancedEventSelectors", []))
            if not basic_s3_data and not advanced_data:
                findings.append(_finding("CLOUDTRAIL_S3_DATA_EVENTS", "Medium", "S3 object data-event telemetry is not enabled", f"Trail {trail['Name']} does not collect S3 object data events. GetObject/PutObject exfiltration detection has no source telemetry.", trail.get("TrailARN", trail["Name"]), "AwsCloudTrailTrail", region, {"s3_data_events": False}, "Enable selective S3 object-level CloudTrail data events for sensitive buckets and route them through EventBridge/Security Lake.", ["CIS AWS 3.10", "PCI DSS 10.2", "SOC 2 CC7.2"]))
    except (BotoCoreError, ClientError) as exc: errors.append({"check": "CLOUDTRAIL", "resource": region, "error": str(exc)})
    try:
        config = session.client("config", region_name=region)
        recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
        statuses = config.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
        recording = any(item.get("recording") for item in statuses)
        if not recorders or not recording:
            findings.append(_finding("AWS_CONFIG_RECORDING", "High", "AWS Config recording is not enabled", f"AWS Config is not actively recording resource configuration changes in {region}.", f"account/{region}", "AwsConfigRecorder", region, {"recorders": len(recorders), "recording": recording}, "Enable AWS Config recording, deliver snapshots to a protected S3 bucket, and deploy managed Config rules for critical controls.", ["CIS AWS 3.5", "PCI DSS 10.2", "SOC 2 CC7.2"]))
    except (BotoCoreError, ClientError) as exc: errors.append({"check": "AWS_CONFIG_RECORDING", "resource": region, "error": str(exc)})
    for service, check_id, title, remediation in [("guardduty", "GUARDDUTY_ENABLED", "Amazon GuardDuty is not enabled", "Enable GuardDuty and designate a delegated administrator for organization-wide coverage."), ("securityhub", "SECURITY_HUB_ENABLED", "AWS Security Hub is not enabled", "Enable Security Hub CSPM, standards, and central configuration for the account.")]:
        try:
            client = session.client(service, region_name=region)
            if service == "guardduty": enabled = any(item.get("Status") == "ENABLED" for item in (client.get_detector(DetectorId=detector_id) for detector_id in client.list_detectors().get("DetectorIds", [])))
            else:
                enabled = client.describe_hub().get("SubscribedAt") is not None
            if not enabled: findings.append(_finding(check_id, "High", title, f"{service} is not active in {region}.", f"account/{region}", "AwsAccount", region, {"enabled": False}, remediation, ["CIS AWS 3.15", "SOC 2 CC7.2"]))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "AWS error")
            if code in {"InvalidAccessException", "ResourceNotFoundException", "BadRequestException"}:
                findings.append(_finding(check_id, "High", title, f"{service} is not active in {region}.", f"account/{region}", "AwsAccount", region, {"api_error": code}, remediation, ["CIS AWS 3.15", "SOC 2 CC7.2"]))
            else: errors.append({"check": check_id, "resource": region, "error": code})
        except BotoCoreError as exc: errors.append({"check": check_id, "resource": region, "error": str(exc)})
    return findings, errors


def run_scan() -> Dict[str, Any]:
    if not _enabled():
        return {"available": False, "reason": "CSPM scanning is disabled. Set CSPM_ENABLED=true and grant the documented read-only IAM policy.", "findings": []}
    session = _session(); regions = _regions(); started = datetime.now(timezone.utc).isoformat(); scan_id = "scan-" + hashlib.sha256(started.encode()).hexdigest()[:16]
    all_findings, errors = _scan_global(session, regions[0])
    for region in regions:
        findings, region_errors = _scan_region(session, region); all_findings.extend(findings); errors.extend(region_errors)
    completed = datetime.now(timezone.utc).isoformat(); account = _account_id(session)
    with _store() as connection:
        connection.execute("INSERT INTO cspm_scans(scan_id,started_at,completed_at,status,account_id,regions,errors) VALUES(?,?,?,?,?,?,?)", (scan_id, started, completed, "completed", account, json.dumps(regions), json.dumps(errors)))
        connection.executemany("INSERT OR REPLACE INTO cspm_findings(finding_id,scan_id,severity,resource,resource_type,check_id,observed_at,doc) VALUES(?,?,?,?,?,?,?,?)", [(item["finding_id"], scan_id, item["severity"], item["resource"], item["resource_type"], item["check_id"], item["observed_at"], json.dumps(item)) for item in all_findings])
    return {"available": True, "scan_id": scan_id, "account_id": account, "regions": regions, "started_at": started, "completed_at": completed, "findings": all_findings, "errors": errors, "summary": _summary(all_findings)}


def _summary(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts = Counter(item.get("severity", "Unknown") for item in findings)
    return {"total": len(findings), "Critical": counts["Critical"], "High": counts["High"], "Medium": counts["Medium"], "Low": counts["Low"], "exposed_resources": sum(1 for item in findings if item.get("exposure"))}


def findings_as_alerts(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Adapt posture failures to the same incident queue as behavioral alerts.

    The finding itself remains the evidence source; this does not pretend a
    configuration issue is a CloudTrail action or assign an unverified attacker.
    """
    alerts = []
    for finding in findings:
        alerts.append({
            "alert_id": f"alert-{finding['finding_id']}", "event_id": finding["finding_id"],
            "timestamp": finding["observed_at"], "event_name": finding["check_id"],
            "event_source": "cloudsentinel.cspm", "threat_name": finding["title"],
            "attack_type": "Cloud Exposure" if finding.get("exposure") else "Cloud Misconfiguration",
            "severity": finding["severity"], "affected_resource": finding["resource"],
            "resource_name": finding["resource"], "source_ip": "posture-scan", "user_name": "CloudSentinel CSPM",
            "what_happened": finding["description"], "mitigation": finding["remediation"],
            "recommended_action": finding["remediation"], "cspm_finding": finding,
            "mitre_attack": [], "ueba": {"score": 0, "reasons": []},
        })
    return alerts


def latest_findings(severity: str = "", resource_type: str = "", search: str = "") -> Dict[str, Any]:
    with _store() as connection:
        scan = connection.execute("SELECT * FROM cspm_scans ORDER BY started_at DESC LIMIT 1").fetchone()
        if not scan: return {"available": _enabled(), "reason": "No CSPM scan has run yet.", "findings": [], "summary": _summary([])}
        findings = [json.loads(row["doc"]) for row in connection.execute("SELECT doc FROM cspm_findings WHERE scan_id=? ORDER BY CASE severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3 WHEN 'Medium' THEN 2 ELSE 1 END DESC, observed_at DESC", (scan["scan_id"],))]
    def match(item: Dict[str, Any]) -> bool:
        haystack = " ".join(str(item.get(key, "")) for key in ("title", "description", "resource", "check_id")).lower()
        return (not severity or item.get("severity", "").lower() == severity.lower()) and (not resource_type or item.get("resource_type", "").lower() == resource_type.lower()) and (not search or search.lower() in haystack)
    findings = [item for item in findings if match(item)]
    return {"available": True, "scan": {"scan_id": scan["scan_id"], "started_at": scan["started_at"], "completed_at": scan["completed_at"], "account_id": scan["account_id"], "regions": json.loads(scan["regions"]), "errors": json.loads(scan["errors"])}, "findings": findings, "summary": _summary(findings)}
