"""Transparent MITRE ATT&CK mappings for AWS activity."""

from __future__ import annotations

from typing import Dict, List

EVENT_MAPPINGS: Dict[str, List[Dict[str, str]]] = {
    "ConsoleLogin": [{"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"}],
    "CreateAccessKey": [{"id": "T1098", "name": "Account Manipulation", "tactic": "Persistence"}, {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"}],
    "AttachRolePolicy": [{"id": "T1098", "name": "Account Manipulation", "tactic": "Privilege Escalation"}],
    "AttachUserPolicy": [{"id": "T1098", "name": "Account Manipulation", "tactic": "Privilege Escalation"}],
    "PutRolePolicy": [{"id": "T1098", "name": "Account Manipulation", "tactic": "Privilege Escalation"}],
    "UpdateAssumeRolePolicy": [{"id": "T1098", "name": "Account Manipulation", "tactic": "Privilege Escalation"}],
    "StopLogging": [{"id": "T1562.008", "name": "Disable or Modify Cloud Logs", "tactic": "Defense Evasion"}],
    "DeleteTrail": [{"id": "T1562.008", "name": "Disable or Modify Cloud Logs", "tactic": "Defense Evasion"}],
    "DeleteBucket": [{"id": "T1485", "name": "Data Destruction", "tactic": "Impact"}],
    "TerminateInstances": [{"id": "T1489", "name": "Service Stop", "tactic": "Impact"}],
    "GetObject": [{"id": "T1530", "name": "Data from Cloud Storage", "tactic": "Collection"}],
}


def mappings_for(event_name: str) -> List[Dict[str, str]]:
    return EVENT_MAPPINGS.get(event_name or "", [])
