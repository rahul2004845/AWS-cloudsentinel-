from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from typing import Any, Dict, Iterable, Tuple
from zoneinfo import ZoneInfo
from mitre import mappings_for

failed_logins_by_ip = defaultdict(deque)
s3_reads_by_ip = defaultdict(deque)
region_by_user = {}

SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

READ_ONLY_PREFIXES = (
    "Get",
    "List",
    "Describe",
    "Lookup",
    "Head",
    "BatchGet",
    "Search",
)

SENSITIVE_IAM_EVENTS = {
    "CreateAccessKey",
    "DeleteAccessKey",
    "UpdateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
    "DeleteLoginProfile",
    "CreateUser",
    "DeleteUser",
    "CreateRole",
    "DeleteRole",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "AttachGroupPolicy",
    "DetachUserPolicy",
    "DetachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "PutGroupPolicy",
    "DeleteUserPolicy",
    "DeleteRolePolicy",
    "DeleteGroupPolicy",
    "AddUserToGroup",
    "RemoveUserFromGroup",
    "CreatePolicy",
    "DeletePolicy",
    "CreatePolicyVersion",
    "DeletePolicyVersion",
    "SetDefaultPolicyVersion",
    "UpdateAssumeRolePolicy",
}

CLOUDTRAIL_TAMPER_EVENTS = {
    "DeleteTrail",
    "StopLogging",
    "UpdateTrail",
    "PutEventSelectors",
    "DeleteEventSelectors",
    "DeleteEventDataStore",
    "UpdateEventDataStore",
}

S3_READ_EVENTS = {"GetObject", "ListObjects", "ListObjectsV2", "ListBucket", "ListBuckets"}
S3_BUCKET_LIFECYCLE_EVENTS = {"CreateBucket", "DeleteBucket"}
S3_PUBLIC_CHANGE_EVENTS = {
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "PutBucketAcl",
    "PutObjectAcl",
    "PutPublicAccessBlock",
    "DeletePublicAccessBlock",
}
S3_SENSITIVE_CHANGE_EVENTS = S3_BUCKET_LIFECYCLE_EVENTS | S3_PUBLIC_CHANGE_EVENTS

SECURITY_GROUP_EVENTS = {
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "RevokeSecurityGroupEgress",
    "CreateSecurityGroup",
    "DeleteSecurityGroup",
}

DESTRUCTIVE_EVENTS = {
    "DeleteBucket",
    "DeleteTrail",
    "StopLogging",
    "DeleteUser",
    "DeleteRole",
    "DeletePolicy",
    "DeleteAccessKey",
    "TerminateInstances",
    "DeleteSecurityGroup",
}

NOISE_EVENT_NAMES = {
    "LookupEvents",
    "DescribeAlarms",
    "DescribeAlarmHistory",
    "DescribeMetricFilters",
    "DescribeRegions",
    "DescribeEnvironments",
    "GetEnvironmentStatus",
    "CreateSession",
    "DeleteSession",
    "SendHeartBeat",
    "PutCredentials",
    "RedeemCode",
    "ListNotificationHubs",
    "CreateLogStream",
    "CreateLogGroup",
    "PutLogEvents",
    "AssumeRole",
    "GetCostAndUsage",
    "GetCostForecast",
    "DescribeOrganization",
    "DescribeRegisteredRegions",
    "DescribeEventAggregates",
    "ListManagedNotificationEvents",
    "GetAccountPlanState",
    "GetAccountColor",
    "ListApplications",
    # Console page-load/configuration reads. Keep actual object access (GetObject,
    # ListObjects*) visible; suppress only the repetitive console plumbing.
    "GetBucketOwnershipControls",
    "GetBucketVersioning",
    "GetBucketPublicAccessBlock",
    "GetBucketEncryption",
    "GetBucketObjectLockConfiguration",
    "GetAccountPublicAccessBlock",
    "ListTagsForResource",
    "GetTrailStatus",
    "DescribeTrails",
    "ListTrails",
    "ListEventDataStores",
    "DescribeAvailabilityZones",
}

AWS_SERVICE_SOURCE_IPS = {
    "events.amazonaws.com",
    "lambda.amazonaws.com",
    "cloudtrail.amazonaws.com",
    "logs.amazonaws.com",
    "monitoring.amazonaws.com",
    "resource-explorer-2.amazonaws.com",
}

NOISE_EVENT_SOURCES = {
    "cloudshell.amazonaws.com",
    "monitoring.amazonaws.com",
    "ce.amazonaws.com",
    "billing.amazonaws.com",
    "notifications.amazonaws.com",
    "resource-explorer-2.amazonaws.com",
}

# The dashboard polls its own Security Hub integration. A denied GetFindings
# read call can otherwise be recorded by CloudTrail and fed back into the SOC
# as an alert every refresh interval. It is integration-health telemetry, not
# a hostile action; Security Hub availability is reported by its own API tab.
INTERNAL_READ_ONLY_OPERATIONS = {("securityhub.amazonaws.com", "GetFindings")}
BEHAVIORAL_ALERT_NAMES = {"Rapid Mutating API Activity", "Off-Hours Mutating AWS Activity", "New Source IP For Privileged Write Activity", "High UEBA Deviation", "Anomalous Region Change For Write Action"}


def is_aws_service_automation(event: Dict[str, Any]) -> bool:
    """AWS-managed service activity has no human behavior baseline."""
    if event.get("external_finding"):
        return False
    user_type = str(event.get("user_type") or "")
    user_name = str(event.get("user_name") or "")
    return user_type == "AWSService" or user_name.startswith("AWSServiceRoleFor")

# Future-impact based rule table. These rules are used to generate explainable alerts.
FUTURE_IMPACT_RULES: Dict[str, Dict[str, str]] = {
    "DeleteBucket": {
        "threat_name": "S3 Bucket Deleted",
        "severity": "High",
        "attack_stage": "Impact / Data Destruction",
        "future_impact": "Data loss, service outage, broken application storage, failed backups, or loss of static website/application assets may happen if the bucket contained production data.",
        "recommended_action": "Verify whether the bucket deletion was approved. Check S3 backups/versioning, review recent IAM activity, and restore the bucket/data if required.",
    },
    "CreateBucket": {
        "threat_name": "New S3 Bucket Created",
        "severity": "Medium",
        "attack_stage": "Resource Creation / Possible Staging",
        "future_impact": "A new storage asset may later be misconfigured, exposed publicly, used to stage data, or used outside approved governance.",
        "recommended_action": "Verify the bucket owner and purpose. Enforce encryption, block public access, tagging, lifecycle policy, and logging.",
    },
    "PutBucketPolicy": {
        "threat_name": "S3 Bucket Policy Modified",
        "severity": "High",
        "attack_stage": "Defense Evasion / Data Exposure",
        "future_impact": "The bucket may become public or allow unauthorized principals to read, write, or delete objects.",
        "recommended_action": "Review the bucket policy diff immediately. Remove public/unknown principals and restore least-privilege access.",
    },
    "PutBucketAcl": {
        "threat_name": "S3 ACL Changed",
        "severity": "High",
        "attack_stage": "Data Exposure",
        "future_impact": "Bucket or object permissions may expose sensitive data to unauthorized users or the public internet.",
        "recommended_action": "Review ACL grants, remove public grants, enable S3 Block Public Access, and prefer IAM/bucket policies over ACLs.",
    },
    "PutObjectAcl": {
        "threat_name": "S3 Object ACL Changed",
        "severity": "High",
        "attack_stage": "Data Exposure",
        "future_impact": "A specific object may become readable or writable by unauthorized users, causing data leakage or object tampering.",
        "recommended_action": "Review the object ACL, remove public/unknown grants, and validate whether the object contains sensitive data.",
    },
    "DeletePublicAccessBlock": {
        "threat_name": "S3 Public Access Block Removed",
        "severity": "Critical",
        "attack_stage": "Defense Evasion / Data Exposure",
        "future_impact": "Future bucket policies or ACLs may expose bucket data publicly because the account/bucket public-access protection was removed.",
        "recommended_action": "Re-enable S3 Block Public Access immediately and review recent bucket policy/ACL changes.",
    },
    "CreateAccessKey": {
        "threat_name": "IAM Access Key Created",
        "severity": "Critical",
        "attack_stage": "Persistence / Credential Access",
        "future_impact": "A long-term credential can be used for persistence, automated access, data theft, or actions outside the console session.",
        "recommended_action": "Verify the access key was approved. Rotate/delete unauthorized keys and review CloudTrail activity by the principal.",
    },
    "AttachRolePolicy": {
        "threat_name": "IAM Privilege Change",
        "severity": "Critical",
        "attack_stage": "Privilege Escalation",
        "future_impact": "The role may gain admin-level or sensitive permissions, allowing privilege escalation or broader cloud compromise.",
        "recommended_action": "Review the attached policy ARN. Remove excessive permissions and validate the role trust policy and recent activity.",
    },
    "AttachUserPolicy": {
        "threat_name": "IAM Privilege Change",
        "severity": "Critical",
        "attack_stage": "Privilege Escalation",
        "future_impact": "The user may gain admin-level or sensitive permissions, allowing privilege escalation, data access, or resource manipulation.",
        "recommended_action": "Review the attached policy ARN. Remove excessive permissions and validate whether the user action was authorized.",
    },
    "AttachGroupPolicy": {
        "threat_name": "IAM Group Privilege Change",
        "severity": "High",
        "attack_stage": "Privilege Escalation",
        "future_impact": "All users in the group may inherit new sensitive permissions, expanding blast radius across multiple identities.",
        "recommended_action": "Review the attached policy and group membership. Remove unauthorized permissions and inspect affected users.",
    },
    "PutRolePolicy": {
        "threat_name": "Inline IAM Role Policy Modified",
        "severity": "Critical",
        "attack_stage": "Privilege Escalation",
        "future_impact": "Inline role permissions may grant stealthy or excessive access that is harder to notice than managed policy attachment.",
        "recommended_action": "Review the inline policy JSON, remove excessive actions/resources, and confirm change approval.",
    },
    "PutUserPolicy": {
        "threat_name": "Inline IAM User Policy Modified",
        "severity": "Critical",
        "attack_stage": "Privilege Escalation",
        "future_impact": "The user may receive stealthy direct permissions that enable privilege escalation, persistence, or data access.",
        "recommended_action": "Review the inline policy JSON, remove unauthorized permissions, and inspect the user's recent activity.",
    },
    "CreateRole": {
        "threat_name": "IAM Role Created",
        "severity": "High",
        "attack_stage": "Persistence / Privilege Escalation Setup",
        "future_impact": "A new role may later be abused for privilege escalation, cross-account access, service impersonation, or persistence.",
        "recommended_action": "Review the role trust policy, attached policies, tags, and creator identity. Delete the role if unauthorized.",
    },
    "UpdateAssumeRolePolicy": {
        "threat_name": "IAM Trust Policy Modified",
        "severity": "Critical",
        "attack_stage": "Privilege Escalation / External Access",
        "future_impact": "External users, AWS accounts, or services may be able to assume the role and gain access to your environment.",
        "recommended_action": "Review trusted principals immediately. Remove unknown accounts/services and enforce external ID/MFA conditions where required.",
    },
    "StopLogging": {
        "threat_name": "CloudTrail Logging Stopped",
        "severity": "Critical",
        "attack_stage": "Defense Evasion",
        "future_impact": "Attackers can hide future activity, reducing audit visibility and making incident investigation difficult.",
        "recommended_action": "Re-enable CloudTrail logging immediately. Investigate the actor and check for follow-up activity during the blind window.",
    },
    "DeleteTrail": {
        "threat_name": "CloudTrail Trail Deleted",
        "severity": "Critical",
        "attack_stage": "Defense Evasion",
        "future_impact": "Audit visibility may be lost and future attacker actions may not be recorded in the expected trail destination.",
        "recommended_action": "Recreate/restore the trail, enable multi-region logging, protect trails with IAM/SCP controls, and investigate the actor.",
    },
    "AuthorizeSecurityGroupIngress": {
        "threat_name": "Security Group Opened",
        "severity": "High",
        "attack_stage": "Initial Access / Exposure",
        "future_impact": "EC2 instances or services may become exposed to the internet, enabling brute force, exploitation, or unauthorized network access.",
        "recommended_action": "Review the new ingress rule. Remove 0.0.0.0/0 or ::/0 exposure for sensitive ports and restrict access to trusted IP ranges.",
    },
}


def stable_hash(value: Any) -> str:
    body = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def parse_time(ts: Any) -> datetime:
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc)
    if not ts:
        return datetime.now(timezone.utc)
    try:
        text = str(ts).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def push_window(store, key: str, now: datetime, seconds: int = 300) -> int:
    store[key].append(now)
    cutoff = now - timedelta(seconds=seconds)
    while store[key] and store[key][0] < cutoff:
        store[key].popleft()
    return len(store[key])


def _json_loads_if_needed(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def _extract_event(raw: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
    raw = dict(raw or {})
    if "CloudTrailEvent" in raw:
        parsed = _json_loads_if_needed(raw.get("CloudTrailEvent"))
        if isinstance(parsed, dict):
            parsed["_lookup_event_id"] = raw.get("EventId")
            parsed["_lookup_event_name"] = raw.get("EventName")
            parsed["_lookup_username"] = raw.get("Username")
            return parsed, "cloudtrail_lookup_events"
    if isinstance(raw.get("detail"), dict):
        d = dict(raw["detail"])
        d["_eventbridge_id"] = raw.get("id")
        d["_eventbridge_account"] = raw.get("account")
        d["_eventbridge_region"] = raw.get("region")
        d["_eventbridge_time"] = raw.get("time")
        d["_eventbridge_source"] = raw.get("source")
        d["_eventbridge_detail_type"] = raw.get("detail-type")
        return d, "eventbridge_cloudtrail"
    return raw, "direct_cloudtrail"


def _extract_username(user_identity: Dict[str, Any]) -> str:
    user_identity = user_identity or {}
    session_context = user_identity.get("sessionContext") or {}
    session_issuer = session_context.get("sessionIssuer") or {}
    return (
        user_identity.get("userName")
        or session_issuer.get("userName")
        or user_identity.get("principalId")
        or user_identity.get("arn")
        or "unknown"
    )


def _activity_status(event: Dict[str, Any], response_elements: Any) -> str:
    if event.get("errorCode") or event.get("errorMessage"):
        return "Failed"
    if isinstance(response_elements, dict):
        console_login = str(response_elements.get("ConsoleLogin") or "")
        if console_login.lower() == "failure":
            return "Failed"
    return "Success"


def _read_only_value(value: Any) -> bool:
    if value is True:
        return True
    if isinstance(value, str) and value.lower() == "true":
        return True
    return False


def _is_read_only_event(event_name: str, read_only: Any) -> bool:
    if _read_only_value(read_only):
        return True
    return event_name.startswith(READ_ONLY_PREFIXES)


def _is_mutating_event(event_name: str, read_only: Any) -> bool:
    return not _is_read_only_event(event_name, read_only)


def _classify_log_type(event_name: str, event_source: str, detail_type: str | None) -> str:
    if detail_type and "Console Signin" in detail_type:
        return "Authentication"
    if event_name == "ConsoleLogin" or event_source == "signin.amazonaws.com":
        return "Authentication"
    if event_name in CLOUDTRAIL_TAMPER_EVENTS or event_source == "cloudtrail.amazonaws.com":
        return "CloudTrail Audit Activity"
    if event_name in SENSITIVE_IAM_EVENTS or event_source == "iam.amazonaws.com":
        return "IAM Security Activity"
    if event_source == "sts.amazonaws.com":
        return "STS Session"
    if event_source == "s3.amazonaws.com":
        if event_name in S3_BUCKET_LIFECYCLE_EVENTS:
            return "S3 Bucket Lifecycle"
        if event_name in S3_PUBLIC_CHANGE_EVENTS:
            return "S3 Security Configuration"
        return "S3 Activity"
    if event_source == "ec2.amazonaws.com" or event_name in SECURITY_GROUP_EVENTS:
        return "EC2 / Network Activity"
    if event_source == "lambda.amazonaws.com":
        return "Lambda Activity"
    if event_source == "logs.amazonaws.com":
        return "CloudWatch Logs"
    if event_source == "monitoring.amazonaws.com":
        return "CloudWatch Monitoring"
    if event_source == "kms.amazonaws.com":
        return "KMS Activity"
    if detail_type and "Console Action" in detail_type:
        return "Console Action"
    return "AWS API Activity"


def _extract_resource_name(event_name: str, event_source: str, request_params: Dict[str, Any], resources: Any) -> str:
    params = request_params or {}
    candidates = [
        params.get("bucketName"),
        params.get("bucket"),
        params.get("key"),
        params.get("roleName"),
        params.get("userName"),
        params.get("groupName"),
        params.get("policyName"),
        params.get("policyArn"),
        params.get("trailName"),
        params.get("eventDataStore"),
        params.get("groupId"),
        params.get("groupName"),
        params.get("functionName"),
        params.get("logGroupName"),
        params.get("logStreamName"),
    ]
    for candidate in candidates:
        if candidate:
            return str(candidate)
    if isinstance(resources, list):
        for resource in resources:
            if isinstance(resource, dict):
                name = resource.get("resourceName") or resource.get("ARN") or resource.get("arn")
                if name:
                    return str(name)
    return "-"


def _summarize_event(event_name: str, event_source: str, params: Dict[str, Any], resource_name: str, status: str) -> str:
    resource = resource_name if resource_name and resource_name != "-" else "target resource"
    explicit_messages = {
        "CreateBucket": f"S3 bucket created: {resource}",
        "DeleteBucket": f"S3 bucket deleted: {resource}",
        "PutBucketPolicy": f"S3 bucket policy updated: {resource}",
        "DeleteBucketPolicy": f"S3 bucket policy deleted: {resource}",
        "PutBucketAcl": f"S3 bucket ACL changed: {resource}",
        "PutObjectAcl": f"S3 object ACL changed: {resource}",
        "PutPublicAccessBlock": f"S3 public access block configured: {resource}",
        "DeletePublicAccessBlock": f"S3 public access block removed: {resource}",
        "GetBucketAcl": f"S3 bucket ACL viewed: {resource}",
        "GetBucketVersioning": f"S3 bucket versioning viewed: {resource}",
        "GetBucketOwnershipControls": f"S3 ownership controls viewed: {resource}",
        "CreateAccessKey": f"IAM access key created for: {resource}",
        "DeleteAccessKey": f"IAM access key deleted for: {resource}",
        "AttachUserPolicy": f"IAM managed policy attached to user: {resource}",
        "AttachRolePolicy": f"IAM managed policy attached to role: {resource}",
        "AttachGroupPolicy": f"IAM managed policy attached to group: {resource}",
        "PutUserPolicy": f"Inline IAM policy added/updated for user: {resource}",
        "PutRolePolicy": f"Inline IAM policy added/updated for role: {resource}",
        "UpdateAssumeRolePolicy": f"IAM role trust policy changed: {resource}",
        "CreateUser": f"IAM user created: {resource}",
        "DeleteUser": f"IAM user deleted: {resource}",
        "CreateRole": f"IAM role created: {resource}",
        "DeleteRole": f"IAM role deleted: {resource}",
        "ConsoleLogin": f"AWS console login {status.lower()}",
        "AssumeRole": f"STS AssumeRole session created: {resource}",
        "AuthorizeSecurityGroupIngress": f"Security group ingress rule added: {resource}",
        "AuthorizeSecurityGroupEgress": f"Security group egress rule added: {resource}",
        "RevokeSecurityGroupIngress": f"Security group ingress rule removed: {resource}",
        "RevokeSecurityGroupEgress": f"Security group egress rule removed: {resource}",
        "CreateSecurityGroup": f"Security group created: {resource}",
        "DeleteSecurityGroup": f"Security group deleted: {resource}",
        "RunInstances": "EC2 instance launched",
        "TerminateInstances": "EC2 instance terminated",
        "DeleteTrail": f"CloudTrail trail deleted: {resource}",
        "StopLogging": f"CloudTrail logging stopped: {resource}",
        "UpdateTrail": f"CloudTrail trail updated: {resource}",
        "CreateLogStream": f"CloudWatch log stream created: {resource}",
        "DeleteLogStream": f"CloudWatch log stream deleted: {resource}",
        "Decrypt": f"KMS decrypt operation performed: {resource}",
        "DescribeAlarms": "CloudWatch alarms listed/viewed",
    }
    if event_name in explicit_messages:
        return explicit_messages[event_name]
    service = event_source.replace(".amazonaws.com", "") if event_source else "AWS"
    return f"{service} API activity: {event_name} on {resource}"


def _noise_reason(event_name: str, event_source: str, source_ip: str, user_name: str, read_only: Any, error_code: Any = None) -> str | None:
    if (event_source, event_name) in INTERNAL_READ_ONLY_OPERATIONS:
        return "CloudSentinel Security Hub integration polling (integration health is shown separately)"
    # Failed requests are operationally/security relevant and must remain visible.
    if error_code:
        return None
    if event_name in {"LookupEvents"}:
        return "CloudSentinel poller/backfill self-generated CloudTrail LookupEvents call"
    if event_name == "AssumeRole" and source_ip in AWS_SERVICE_SOURCE_IPS:
        return f"AWS service role assumption generated by {source_ip}"
    if event_name in {"CreateLogStream", "CreateLogGroup", "PutLogEvents"} and event_source == "logs.amazonaws.com":
        return "CloudWatch log delivery/runtime logging background event"
    if event_name == "Decrypt" and "cloudsentinel" in user_name.lower():
        return "CloudSentinel runtime KMS decrypt activity"
    if event_source == "cloudshell.amazonaws.com" and event_name in {
        "SendHeartBeat", "PutCredentials", "RedeemCode", "GetEnvironmentStatus",
        "CreateSession", "DeleteSession", "DescribeEnvironments",
    }:
        return "AWS CloudShell background/session event"
    if event_source == "monitoring.amazonaws.com" and event_name.startswith("Describe"):
        return "AWS Console/CloudWatch dashboard read-only polling event"
    if event_name in NOISE_EVENT_NAMES and _is_read_only_event(event_name, read_only):
        return "read-only AWS console/background event"
    if _is_read_only_event(event_name, read_only) and event_source in NOISE_EVENT_SOURCES:
        return "read-only AWS console/background event"
    return None


def normalize_event(raw: Dict[str, Any]) -> Dict[str, Any]:
    event, source_format = _extract_event(raw)
    event_time = event.get("eventTime") or event.get("_eventbridge_time")
    now = parse_time(event_time)

    user_identity = event.get("userIdentity") or {}
    request_params = _json_loads_if_needed(event.get("requestParameters") or {})
    response_elements = _json_loads_if_needed(event.get("responseElements") or {})
    if not isinstance(request_params, dict):
        request_params = {}
    if not isinstance(response_elements, dict):
        response_elements = {}

    event_name = event.get("eventName") or event.get("_lookup_event_name") or "UnknownEvent"
    event_source = event.get("eventSource") or event.get("_eventbridge_source") or event.get("source") or "unknown"
    detail_type = event.get("_eventbridge_detail_type")
    event_id = (
        event.get("eventID")
        or event.get("eventId")
        or event.get("_eventbridge_id")
        or event.get("_lookup_event_id")
        or stable_hash(event)
    )
    resources = event.get("resources") or []
    status = _activity_status(event, response_elements)
    external_finding = event.get("external_finding") or {}
    resource_name = external_finding.get("resource") or _extract_resource_name(event_name, event_source, request_params, resources)
    source_ip = event.get("sourceIPAddress") or "unknown"
    read_only = event.get("readOnly")
    noise_reason = _noise_reason(event_name, event_source, source_ip, _extract_username(user_identity), read_only, event.get("errorCode"))

    normalized = {
        "event_id": str(event_id),
        "timestamp": now.isoformat(),
        "event_name": event_name,
        "event_source": event_source,
        "log_type": _classify_log_type(event_name, event_source, detail_type),
        "activity_status": status,
        "activity_detail": _summarize_event(event_name, event_source, request_params, resource_name, status),
        "resource_name": resource_name,
        "is_mutating_event": _is_mutating_event(event_name, read_only),
        "source_ip": source_ip,
        "region": event.get("awsRegion") or event.get("_eventbridge_region") or "unknown",
        "account_id": event.get("recipientAccountId") or event.get("_eventbridge_account") or "unknown",
        "user_arn": user_identity.get("arn") or "unknown",
        "user_name": _extract_username(user_identity),
        "user_type": user_identity.get("type") or "unknown",
        "error_code": event.get("errorCode"),
        "error_message": event.get("errorMessage"),
        "read_only": read_only,
        "is_noise_event": bool(noise_reason),
        "noise_reason": noise_reason,
        "event_category": event.get("eventCategory"),
        "request_parameters": request_params,
        "response_elements": response_elements,
        "resources": resources,
        "source_format": source_format,
        "external_finding": event.get("external_finding"),
        "threat_detected": False,
        "threat_types": [],
        "max_severity": None,
        "raw": raw,
    }
    return normalized


def is_dashboard_event(event: Dict[str, Any]) -> bool:
    """Return whether an event belongs in the clean analyst-facing activity feed."""
    if (str(event.get("event_source") or ""), str(event.get("event_name") or "")) in INTERNAL_READ_ONLY_OPERATIONS:
        return False
    if is_aws_service_automation(event) and _is_read_only_event(str(event.get("event_name") or ""), event.get("read_only")):
        return False
    if event.get("threat_detected") or event.get("activity_status") == "Failed":
        return True
    if event.get("is_noise_event"):
        return False
    name = str(event.get("event_name") or "")
    source = str(event.get("event_source") or "")
    # Also clean historical records ingested before the current noise marker existed.
    if name in NOISE_EVENT_NAMES and _is_read_only_event(name, event.get("read_only")):
        return False
    if source in NOISE_EVENT_SOURCES and _is_read_only_event(name, event.get("read_only")):
        return False
    return True


def _is_failed_console_login(event: Dict[str, Any]) -> bool:
    if event.get("event_name") != "ConsoleLogin":
        return False
    error_code = str(event.get("error_code") or "")
    error_message = str(event.get("error_message") or "")
    response = event.get("response_elements") or {}
    console_login_result = str(response.get("ConsoleLogin") or "")
    return (
        error_code == "FailedAuthentication"
        or console_login_result.lower() == "failure"
        or "failed" in error_message.lower()
    )


def _root_alert_enabled_for_read_only() -> bool:
    return os.getenv("ALERT_ROOT_READ_ONLY", "false").lower() in {"1", "true", "yes", "on"}


def _is_root_security_relevant(event: Dict[str, Any]) -> bool:
    if event.get("user_type") != "Root":
        return False
    if event.get("is_noise_event"):
        return False
    if event.get("event_name") == "ConsoleLogin":
        return True
    if event.get("is_mutating_event"):
        return True
    return _root_alert_enabled_for_read_only()


def _security_group_open_to_world(event: Dict[str, Any]) -> Tuple[bool, str | None]:
    if event.get("event_name") not in {"AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"}:
        return False, None
    params = event.get("request_parameters") or {}
    text = json.dumps(params, default=str)
    open_to_world = "0.0.0.0/0" in text or "::/0" in text
    risky_port = any(port in text for port in ['"fromPort": 22', '"toPort": 22', '"fromPort": 3389', '"toPort": 3389'])
    if open_to_world:
        exposure = "SSH/RDP open to world" if risky_port else "security group rule open to world"
        return True, exposure
    return False, None


def _s3_public_change(event: Dict[str, Any]) -> Tuple[bool, str | None]:
    if event.get("event_name") not in S3_PUBLIC_CHANGE_EVENTS:
        return False, None
    text = json.dumps(event.get("request_parameters") or {}, default=str).lower()
    if "public-read" in text or "public-read-write" in text or '"principal": "*"' in text or '"principal":"*"' in text:
        return True, "public S3 bucket/object access policy or ACL pattern"
    if event.get("event_name") == "DeletePublicAccessBlock":
        return True, "S3 public access block removed"
    return False, None


def _unauthorized_api_call(event: Dict[str, Any]) -> bool:
    error_code = str(event.get("error_code") or "")
    error_message = str(event.get("error_message") or "")
    text = f"{error_code} {error_message}"
    return any(token in text for token in ["AccessDenied", "Unauthorized", "Denied", "not authorized"])


def make_alert(
    event: Dict[str, Any],
    threat_name: str,
    severity: str,
    what_happened: str,
    future_impact: str,
    recommended_action: str,
    attack_stage: str,
    now: datetime,
) -> Dict[str, Any]:
    affected_resource = event.get("resource_name") or "-"
    alert = {
        "timestamp": now.isoformat(),
        "event_id": event.get("event_id"),
        "source_ip": event.get("source_ip"),
        "user_arn": event.get("user_arn"),
        "user_name": event.get("user_name"),
        "user_type": event.get("user_type"),
        "event_name": event.get("event_name"),
        "event_source": event.get("event_source"),
        "log_type": event.get("log_type"),
        "activity_status": event.get("activity_status"),
        "activity_detail": event.get("activity_detail"),
        "resource_name": affected_resource,
        "affected_resource": affected_resource,
        "region": event.get("region"),
        "account_id": event.get("account_id"),
        # Old keys kept for compatibility with existing dashboard/email code.
        "attack_type": threat_name,
        "description": what_happened,
        "mitigation": recommended_action,
        # New future-impact fields.
        "threat_name": threat_name,
        "severity": severity,
        "what_happened": what_happened,
        "future_impact": future_impact,
        "recommended_action": recommended_action,
        "attack_stage": attack_stage,
        "email_status": "not_attempted",
        "mitre_attack": mappings_for(event.get("event_name") or ""),
        "ueba": event.get("ueba", {}),
    }
    alert["alert_id"] = stable_hash({
        "event_id": alert["event_id"],
        "threat_name": threat_name,
        "source_ip": alert["source_ip"],
        "affected_resource": alert["affected_resource"],
    })
    return alert


def detect_behavioral_threats(event: Dict[str, Any], history: Iterable[Dict[str, Any]]) -> list[Dict[str, Any]]:
    """Detect explainable deviations from the account's own observed activity.

    This is deliberately deterministic: it compares the event with retained
    CloudTrail history and fixed, configurable thresholds. No model is trained
    or used at runtime.
    """
    if event.get("is_noise_event"):
        return []

    now = parse_time(event.get("timestamp"))
    user = str(event.get("user_arn") or "unknown")
    source_ip = str(event.get("source_ip") or "unknown")
    min_history = max(1, int(os.getenv("BEHAVIOR_MIN_HISTORY", "5")))
    window_seconds = max(60, int(os.getenv("BEHAVIOR_MUTATION_WINDOW_SECONDS", "300")))
    mutation_threshold = max(2, int(os.getenv("BEHAVIOR_MUTATION_THRESHOLD", "6")))
    prior = [item for item in history if item.get("event_id") != event.get("event_id")]
    actor_history = [item for item in prior if str(item.get("user_arn") or "unknown") == user]
    alerts: list[Dict[str, Any]] = []

    # A new source IP becomes significant only after an identity has an observed baseline.
    known_ips = {str(item.get("source_ip")) for item in actor_history if item.get("source_ip")}
    if user != "unknown" and len(actor_history) >= min_history and source_ip not in known_ips and event.get("is_mutating_event"):
        alerts.append(make_alert(
            event, "New Source IP For Privileged Write Activity", "High",
            f"{user} performed a mutating {event.get('event_name')} action from previously unseen source IP {source_ip} after {len(actor_history)} observed historical events.",
            "The credentials may be used from an unapproved host, network, proxy, or attacker-controlled system.",
            "Validate the user and source IP, review the session and revoke credentials or sessions if the activity is not authorized.",
            "Behavioral Anomaly", now,
        ))

    # Detect an unusual burst of writes by the same identity within the retained history window.
    recent_mutations = [
        item for item in actor_history
        if item.get("is_mutating_event") and parse_time(item.get("timestamp")) >= now - timedelta(seconds=window_seconds)
    ]
    if user != "unknown" and event.get("is_mutating_event") and len(recent_mutations) + 1 >= mutation_threshold:
        alerts.append(make_alert(
            event, "Rapid Mutating API Activity", "High",
            f"{user} generated {len(recent_mutations) + 1} mutating AWS API actions within {window_seconds // 60} minutes.",
            "A rapid control-plane change burst can indicate scripted abuse, destructive activity, or compromised automation credentials.",
            "Review the sequence of API calls, validate the automation/change ticket, and suspend the principal if the burst is unexpected.",
            "Behavioral Anomaly", now,
        ))

    # Off-hours only alerts for identities that have enough history; timezone is explicit/configurable.
    try:
        local_time = now.astimezone(ZoneInfo(os.getenv("BEHAVIOR_TIMEZONE", "Asia/Kolkata")))
        start = int(os.getenv("BEHAVIOR_OFF_HOURS_START", "20"))
        end = int(os.getenv("BEHAVIOR_OFF_HOURS_END", "7"))
        off_hours = local_time.hour >= start or local_time.hour < end if start > end else start <= local_time.hour < end
        if user != "unknown" and len(actor_history) >= min_history and event.get("is_mutating_event") and off_hours:
            alerts.append(make_alert(
                event, "Off-Hours Mutating AWS Activity", "Medium",
                f"{user} performed {event.get('event_name')} at {local_time.strftime('%H:%M %Z')}, outside the configured business-hours baseline.",
                "Unexpected off-hours control-plane actions may indicate unauthorized access or unapproved automation.",
                "Validate the change window and actor. If unexpected, investigate the session and related CloudTrail events.",
                "Behavioral Anomaly", now,
            ))
    except Exception:
        # Invalid timezone configuration must not interrupt security ingestion.
        pass
    return alerts


def _event_rule_alert(event: Dict[str, Any], now: datetime) -> Dict[str, Any] | None:
    rule = FUTURE_IMPACT_RULES.get(event.get("event_name") or "")
    if not rule:
        return None

    actor = event.get("user_name") or event.get("user_arn") or "unknown"
    source_ip = event.get("source_ip") or "unknown"
    resource = event.get("resource_name") or "-"
    event_name = event.get("event_name") or "UnknownEvent"
    region = event.get("region") or "unknown"

    what_happened = (
        f"{event.get('activity_detail') or event_name}. "
        f"Actor={actor}, source_ip={source_ip}, region={region}, affected_resource={resource}."
    )

    return make_alert(
        event=event,
        threat_name=rule["threat_name"],
        severity=rule["severity"],
        what_happened=what_happened,
        future_impact=rule["future_impact"],
        recommended_action=rule["recommended_action"],
        attack_stage=rule["attack_stage"],
        now=now,
    )


def enrich_event_with_alerts(event: Dict[str, Any], alerts: list[Dict[str, Any]]) -> Dict[str, Any]:
    event = dict(event)
    event["threat_detected"] = bool(alerts)
    event["threat_types"] = [a.get("threat_name") or a.get("attack_type") for a in alerts if a.get("threat_name") or a.get("attack_type")]
    if alerts:
        event["max_severity"] = max(
            (a.get("severity", "Low") for a in alerts),
            key=lambda sev: SEVERITY_RANK.get(sev, 0),
        )
        event["future_impacts"] = [a.get("future_impact") for a in alerts if a.get("future_impact")]
        event["recommended_actions"] = [a.get("recommended_action") for a in alerts if a.get("recommended_action")]
    else:
        event["max_severity"] = None
        event["future_impacts"] = []
        event["recommended_actions"] = []
    return event


def detect_threats(event: Dict[str, Any], history: Iterable[Dict[str, Any]] = ()) -> list[Dict[str, Any]]:
    if event.get("is_noise_event"):
        return []

    now = parse_time(event.get("timestamp"))
    external = event.get("external_finding") or {}
    # Security Hub/GuardDuty findings are already detections. They must retain
    # their original AWS severity, but must not be evaluated as human IAM/UEBA
    # behavior (which created false rapid/off-hours alerts for aws.securityhub).
    if external:
        event["ueba"] = {"score": 0, "baseline_ready": False, "reasons": ["AWS-managed finding; excluded from human behavior baseline"]}
        native_severity = str(external.get("severity", "Medium")).title()
        # Low/informational provider findings remain searchable in the native
        # Security Hub view, but do not create SOC alerts/incidents or mail.
        if SEVERITY_RANK.get(native_severity, 1) < SEVERITY_RANK["Medium"]:
            return []
        return [make_alert(
            event, f"{external.get('provider', 'AWS')} Finding: {external.get('title', 'Security Finding')}", native_severity,
            str(external.get("description") or "AWS security service reported a finding."),
            "The AWS-managed detection indicates suspicious activity or a security control failure that requires investigation.",
            "Review the original finding in AWS, validate the affected resource, contain unauthorized access, and close the finding only after remediation.",
            "AWS Native Detection", now,
        )]

    # AWS service roles can legitimately perform bursty or off-hours automated
    # reads. Keep them in raw audit storage but do not alert on them as users.
    if is_aws_service_automation(event):
        event["ueba"] = {"score": 0, "baseline_ready": False, "reasons": ["AWS service automation; excluded from UEBA"]}
        return []

    # Import locally to avoid a module import cycle while preserving the simple
    # detector API used by the ingestion service.
    from ueba import score_event
    event["ueba"] = score_event(event, history)

    alerts: list[Dict[str, Any]] = []
    event_name = event.get("event_name") or "UnknownEvent"
    event_source = event.get("event_source") or "unknown"
    source_ip = event.get("source_ip") or "unknown"
    region = event.get("region") or "unknown"
    user_arn = event.get("user_arn") or "unknown"
    resource_name = event.get("resource_name") or "-"

    # Native AWS detections are preserved as explainable CloudSentinel alerts.
    # 1. Direct future-impact rule table.
    direct_alert = _event_rule_alert(event, now)
    if direct_alert:
        alerts.append(direct_alert)

    # 2. Brute-force login detection: repeated failed ConsoleLogin.
    if _is_failed_console_login(event):
        count = push_window(failed_logins_by_ip, source_ip, now, 300)
        if count >= 5:
            alerts.append(make_alert(
                event,
                "Brute Force Attempt",
                "High",
                f"{count} failed AWS ConsoleLogin attempts were observed from {source_ip} within 5 minutes.",
                "Account compromise may happen if the password is guessed or if MFA is not enforced.",
                "Enable MFA, block/review the source IP, rotate credentials if needed, and inspect IAM sign-in history.",
                "Credential Access / Initial Access",
                now,
            ))

    # 3. Public S3 exposure special handling for policies/ACLs.
    s3_public, s3_reason = _s3_public_change(event)
    if s3_public and event_name not in {"PutBucketPolicy", "PutBucketAcl", "PutObjectAcl", "DeletePublicAccessBlock"}:
        alerts.append(make_alert(
            event,
            "Public S3 Exposure Change",
            "High",
            f"Potential {s3_reason}. {event.get('activity_detail')}",
            "Sensitive bucket/object data may become accessible to unauthorized users or the public internet.",
            "Review bucket policy/ACL/public-access-block settings and restore least-privilege access.",
            "Data Exposure",
            now,
        ))

    # 4. CloudTrail tampering variants not in direct table.
    if event_name in CLOUDTRAIL_TAMPER_EVENTS and event_name not in {"StopLogging", "DeleteTrail"}:
        alerts.append(make_alert(
            event,
            "CloudTrail Audit Configuration Modified",
            "Critical",
            f"CloudTrail/audit logging configuration was modified: {event.get('activity_detail')}",
            "Security monitoring visibility may be reduced, allowing suspicious future activity to be missed.",
            "Verify the change, restore approved audit settings, and investigate the principal that modified CloudTrail.",
            "Defense Evasion",
            now,
        ))

    # 5. Security group events: open-to-world is high risk; other mutating SG change is medium.
    sg_open, sg_reason = _security_group_open_to_world(event)
    if sg_open:
        alerts.append(make_alert(
            event,
            "Public Security Group Exposure",
            "High",
            f"{sg_reason} detected. {event.get('activity_detail')}",
            "Publicly exposed ports can allow brute force, exploitation, lateral movement, or direct access to cloud workloads.",
            "Restrict the security group CIDR range to trusted IPs and remove public SSH/RDP exposure.",
            "Initial Access / Exposure",
            now,
        ))
    elif event_name in SECURITY_GROUP_EVENTS and event.get("is_mutating_event") and event_name not in FUTURE_IMPACT_RULES:
        alerts.append(make_alert(
            event,
            "Security Group Configuration Change",
            "Medium",
            f"{event.get('activity_detail')}. Source IP={source_ip}.",
            "Network exposure or connectivity may change, which can either break workloads or expose services unexpectedly.",
            "Review the security group rule diff and confirm the network change was approved.",
            "Network Configuration Change",
            now,
        ))

    # 6. Sensitive IAM fallback for IAM events not explicitly mapped.
    if event_name in SENSITIVE_IAM_EVENTS and event_name not in FUTURE_IMPACT_RULES:
        alerts.append(make_alert(
            event,
            "Sensitive IAM Change",
            "Critical",
            f"Sensitive IAM control-plane change detected: {event.get('activity_detail')}",
            "Permissions, identities, or credentials may be changed in a way that enables privilege escalation, persistence, or unauthorized access.",
            "Validate the actor, revert unauthorized IAM changes, and rotate exposed credentials if required.",
            "Privilege Escalation / Persistence",
            now,
        ))

    # 7. Root account activity. Default: mutating root actions and root login only.
    if _is_root_security_relevant(event):
        severity = "Critical" if event.get("is_mutating_event") else "High"
        alerts.append(make_alert(
            event,
            "Root Account Activity",
            severity,
            f"AWS root account performed security-relevant activity: {event.get('activity_detail')}",
            "Root has full account control. If compromised or misused, attackers can disable security controls, change billing/security settings, delete resources, or create persistent access.",
            "Avoid root usage, verify MFA, review recent root events, and move daily operations to least-privilege IAM roles/users.",
            "Privileged Account Activity",
            now,
        ))

    # 8. Unauthorized API calls.
    if _unauthorized_api_call(event):
        alerts.append(make_alert(
            event,
            "Unauthorized API Attempt",
            "Medium",
            f"AWS denied or unauthorized API call: {event.get('activity_detail')}. Error={event.get('error_code')}",
            "Repeated denied calls may indicate reconnaissance, incorrect permissions, or attempted access to restricted cloud resources.",
            "Review the principal permissions and confirm whether this is expected testing or suspicious access.",
            "Reconnaissance / Unauthorized Access Attempt",
            now,
        ))

    # 9. High-volume S3 reads.
    if event_source == "s3.amazonaws.com" and event_name in S3_READ_EVENTS:
        count = push_window(s3_reads_by_ip, source_ip, now, 300)
        if count >= 20:
            alerts.append(make_alert(
                event,
                "Possible S3 Data Exfiltration",
                "Critical",
                f"High-volume S3 read/list pattern from {source_ip}: {count} S3 read/list events within 5 minutes.",
                "Large-scale data access may indicate exfiltration, credential abuse, or automated scraping of bucket contents.",
                "Review bucket access, inspect object access patterns, and suspend suspicious credentials if needed.",
                "Collection / Exfiltration",
                now,
            ))

    # 10. Region anomaly only for mutating actions.
    if user_arn != "unknown" and region != "unknown" and event.get("is_mutating_event"):
        previous_region = region_by_user.get(user_arn)
        if previous_region and previous_region != region:
            alerts.append(make_alert(
                event,
                "Anomalous Region Change For Write Action",
                "Medium",
                f"Principal performed a mutating API call from a new region: previous={previous_region}, current={region}, event={event_name}.",
                "A sudden write action in a new region may indicate compromised credentials, accidental deployment, or unauthorized resource creation.",
                "Confirm whether the region change is expected and review recent session activity.",
                "Behavioral Anomaly",
                now,
            ))
        region_by_user[user_arn] = region

    # 11. Deterministic behavioral rules based on retained CloudTrail history.
    alerts.extend(detect_behavioral_threats(event, history))

    if event["ueba"].get("baseline_ready") and event["ueba"].get("score", 0) >= 60:
        alerts.append(make_alert(
            event, "High UEBA Deviation", "High",
            "; ".join(event["ueba"].get("reasons", [])),
            "The action substantially deviates from the identity's observed AWS behavior and may indicate credential misuse or an unapproved change.",
            "Validate the user, source IP, region, and change request. Contain the principal if the activity is unauthorized.",
            "Behavioral Anomaly", now,
        ))

    # Deduplicate alerts by alert_id.
    unique = {}
    for alert in alerts:
        unique[alert["alert_id"]] = alert
    return list(unique.values())
