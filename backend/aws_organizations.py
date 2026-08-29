"""Read-only AWS Organizations inventory for CloudSentinel multi-account views."""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict, List


def _enabled() -> bool:
    return os.getenv("ORGANIZATIONS_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}


def organization_accounts() -> Dict[str, Any]:
    """List accounts visible to the configured management/delegated-admin identity."""
    if not _enabled():
        return {"enabled": False, "available": False, "accounts": [], "message": "Set ORGANIZATIONS_ENABLED=true in the central monitoring account."}
    try:
        import boto3
        client = boto3.Session(profile_name=os.getenv("AWS_PROFILE") or None, region_name=os.getenv("AWS_REGION", "ap-south-1")).client("organizations")
        accounts: List[Dict[str, Any]] = []
        for page in client.get_paginator("list_accounts").paginate():
            for account in page.get("Accounts", []):
                accounts.append({"account_id": account.get("Id"), "name": account.get("Name"), "email": account.get("Email"), "status": account.get("Status"), "joined_method": account.get("JoinedMethod"), "joined_timestamp": account.get("JoinedTimestamp").isoformat() if account.get("JoinedTimestamp") else None})
        return {"enabled": True, "available": True, "retrieved_at": datetime.now(timezone.utc).isoformat(), "account_count": len(accounts), "accounts": accounts}
    except Exception as exc:
        return {"enabled": True, "available": False, "accounts": [], "message": "The configured AWS identity must be a management account or delegated Organizations administrator with organizations:ListAccounts.", "error": str(exc)}
