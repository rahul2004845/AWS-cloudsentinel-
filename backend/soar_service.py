"""Approval-gated AWS response actions for CloudSentinel.

Nothing in this module performs a cloud change unless SOAR_EXECUTION_ENABLED is
explicitly true and a separate administrator approves the queued action.
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from database import SQLITE_PATH

SUPPORTED_ACTIONS = {
    "disable_iam_access_key": {"label": "Disable IAM access key", "required": ["user_name", "access_key_id"]},
    "block_s3_public_access": {"label": "Block public S3 access", "required": ["bucket_name"]},
    "quarantine_ec2_instance": {"label": "Quarantine EC2 instance", "required": ["instance_id", "quarantine_security_group_id", "region"]},
}


def _enabled(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _conn():
    conn = sqlite3.connect(str(SQLITE_PATH)); conn.row_factory = sqlite3.Row
    return conn


def init_soar_store() -> None:
    with _conn() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS soar_actions (
            action_id TEXT PRIMARY KEY, incident_id TEXT, action_type TEXT NOT NULL,
            status TEXT NOT NULL, requested_by TEXT, approved_by TEXT, requested_at TEXT NOT NULL,
            approved_at TEXT, executed_at TEXT, parameters TEXT NOT NULL, reason TEXT, result TEXT)""")


init_soar_store()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row(row) -> Dict[str, Any]:
    item = dict(row); item["parameters"] = json.loads(item["parameters"]); item["result"] = json.loads(item["result"]) if item.get("result") else None
    item["action_label"] = SUPPORTED_ACTIONS.get(item["action_type"], {}).get("label", item["action_type"])
    return item


def list_actions(incident_id: str = "", limit: int = 100) -> List[Dict[str, Any]]:
    query = "SELECT * FROM soar_actions"; params: tuple = ()
    if incident_id: query += " WHERE incident_id=?"; params = (incident_id,)
    query += " ORDER BY requested_at DESC LIMIT ?"; params += (limit,)
    with _conn() as conn: return [_row(row) for row in conn.execute(query, params)]


def request_action(incident_id: str, action_type: str, parameters: Dict[str, Any], requested_by: str, reason: str = "") -> Dict[str, Any]:
    template = SUPPORTED_ACTIONS.get(action_type)
    if not template: raise ValueError(f"Unsupported action_type. Supported: {', '.join(SUPPORTED_ACTIONS)}")
    missing = [key for key in template["required"] if not str(parameters.get(key, "")).strip()]
    if missing: raise ValueError(f"Missing required action parameters: {', '.join(missing)}")
    if not str(requested_by).strip(): raise ValueError("requested_by is required for an approval audit trail")
    action_id = f"soar-{uuid.uuid4().hex[:16]}"; now = _now()
    with _conn() as conn:
        conn.execute("INSERT INTO soar_actions(action_id,incident_id,action_type,status,requested_by,requested_at,parameters,reason) VALUES(?,?,?,?,?,?,?,?)", (action_id, incident_id, action_type, "Pending Approval", requested_by, now, json.dumps(parameters), reason))
        row = conn.execute("SELECT * FROM soar_actions WHERE action_id=?", (action_id,)).fetchone()
    return _row(row)


def _client(service: str, region: str = ""):
    profile = os.getenv("AWS_PROFILE"); session = boto3.Session(profile_name=profile) if profile else boto3.Session()
    return session.client(service, region_name=region or os.getenv("AWS_REGION", "ap-south-1"))


def _execute(action_type: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
    if action_type == "disable_iam_access_key":
        _client("iam").update_access_key(UserName=parameters["user_name"], AccessKeyId=parameters["access_key_id"], Status="Inactive")
        return {"message": "IAM access key was set to Inactive."}
    if action_type == "block_s3_public_access":
        _client("s3").put_public_access_block(Bucket=parameters["bucket_name"], PublicAccessBlockConfiguration={"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True})
        return {"message": "S3 Block Public Access was enabled for the bucket."}
    if action_type == "quarantine_ec2_instance":
        _client("ec2", parameters["region"]).modify_instance_attribute(InstanceId=parameters["instance_id"], Groups=[parameters["quarantine_security_group_id"]])
        return {"message": "EC2 instance security groups were replaced with the approved quarantine security group."}
    raise ValueError("Unsupported action_type")


def approve_action(action_id: str, approved_by: str) -> Dict[str, Any]:
    if not str(approved_by).strip(): raise ValueError("approved_by is required")
    with _conn() as conn:
        row = conn.execute("SELECT * FROM soar_actions WHERE action_id=?", (action_id,)).fetchone()
        if not row: raise ValueError("SOAR action not found")
        action = _row(row)
        if action["status"] != "Pending Approval": raise ValueError(f"action is already {action['status']}")
        if _enabled("SOAR_REQUIRE_SEPARATE_APPROVER", "true") and action["requested_by"] == approved_by: raise ValueError("a separate approver is required")
        conn.execute("UPDATE soar_actions SET status=?,approved_by=?,approved_at=? WHERE action_id=?", ("Approved", approved_by, _now(), action_id))
    if not _enabled("SOAR_EXECUTION_ENABLED"):
        return {"action_id": action_id, "status": "Approved", "message": "Approval recorded. Execution is disabled by SOAR_EXECUTION_ENABLED=false."}
    try:
        result = _execute(action["action_type"], action["parameters"])
        with _conn() as conn: conn.execute("UPDATE soar_actions SET status=?,executed_at=?,result=? WHERE action_id=?", ("Executed", _now(), json.dumps(result), action_id))
        return {"action_id": action_id, "status": "Executed", "result": result}
    except (ClientError, BotoCoreError, ValueError) as exc:
        result = {"error": str(exc)}
        with _conn() as conn: conn.execute("UPDATE soar_actions SET status=?,result=? WHERE action_id=?", ("Failed", json.dumps(result), action_id))
        return {"action_id": action_id, "status": "Failed", "result": result}


def reject_action(action_id: str, rejected_by: str, reason: str = "") -> Dict[str, Any]:
    with _conn() as conn:
        row = conn.execute("SELECT status FROM soar_actions WHERE action_id=?", (action_id,)).fetchone()
        if not row: raise ValueError("SOAR action not found")
        if row["status"] != "Pending Approval": raise ValueError(f"action is already {row['status']}")
        conn.execute("UPDATE soar_actions SET status=?,approved_by=?,approved_at=?,result=? WHERE action_id=?", ("Rejected", rejected_by, _now(), json.dumps({"reason": reason}), action_id))
    return {"action_id": action_id, "status": "Rejected"}
