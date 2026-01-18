import json
import os
import time
from typing import Any, Dict, List

import requests

SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")

def require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"{name} environment variable not set")
    return value


def send_event(event: Dict[str, Any]) -> None:
    """Send a single normalized event to Splunk HEC."""
    hec_url = require_env("SPLUNK_HEC_URL")
    hec_token = require_env("SPLUNK_HEC_TOKEN")

    payload = {
        "time": int(time.time()),
        "event": event,
    }

    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json",
    }
    
    resp = requests.post(
        hec_url,
        headers=headers,
        data=json.dumps(payload),
        verify=False,
    )

    print("Status:", resp.status_code, resp.text)


def map_cloudtrail_to_normalized(record: Dict[str, Any]) -> Dict[str, Any]:
    """Map a single CloudTrail record into our normalized schema, with enriched severity."""

    event_name = record.get("eventName", "UnknownEvent")
    event_time = record.get("eventTime", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    event_source = record.get("eventSource", "unknown")

    user_identity = record.get("userIdentity", {}) or {}
    request_params = record.get("requestParameters", {}) or {}

    # Actor: prefer ARN, fall back to userName, then 'unknown'
    actor = (
        user_identity.get("arn")
        or user_identity.get("userName")
        or "unknown_actor"
    )

    # Target: for IAM, often the userName in the requestParameters
    target = request_params.get("userName") or "unknown_target"

    # Category: IAM if coming from iam.amazonaws.com, else generic cloudtrail
    if event_source == "iam.amazonaws.com":
        category = "iam"
    else:
        category = "cloudtrail"

    # ------------------------------------------------------------------
    # Severity logic
    # ------------------------------------------------------------------
    # Goal:
    # - IAM reads/lists  -> low
    # - IAM writes       -> medium
    # - Privilege/cred changes -> high
    # - Everything else  -> medium by default
    # ------------------------------------------------------------------

    event_name_lower = event_name.lower()

    # CloudTrail flags
    read_only = bool(record.get("readOnly", False))
    management_event = bool(record.get("managementEvent", True))

    # Define sets of high-risk IAM actions
    privilege_actions = {
        # Policy / permission changes
        "AttachUserPolicy",
        "DetachUserPolicy",
        "PutUserPolicy",
        "DeleteUserPolicy",
        "PutUserPermissionsBoundary",
        "DeleteUserPermissionsBoundary",
        # Role/privilege style actions (if ever ingested here)
        "AttachRolePolicy",
        "DetachRolePolicy",
        "PutRolePolicy",
        "DeleteRolePolicy",
    }

    credential_actions = {
        "CreateAccessKey",
        "DeleteAccessKey",
        "UpdateLoginProfile",
        "CreateLoginProfile",
        "ResetServiceSpecificCredential",
    }

    user_lifecycle_actions = {
        "CreateUser",
        "DeleteUser",
        "UpdateUser",
    }

    # Default severity
    severity = "medium"

    # 1) Obvious reads/lists/describe or explicitly readOnly -> low
    if (
        read_only
        or event_name_lower.startswith("get")
        or event_name_lower.startswith("list")
        or event_name_lower.startswith("describe")
    ):
        severity = "low"

    # 2) IAM privilege/credential changes -> high
    elif event_source == "iam.amazonaws.com" and (
        event_name in privilege_actions
        or event_name in credential_actions
        or event_name in user_lifecycle_actions
    ):
        severity = "high"

    # 3) Other IAM write management events -> medium (elevated above reads)
    elif event_source == "iam.amazonaws.com" and management_event and not read_only:
        severity = "medium"

    # 4) Non-IAM events:
    #    Keep medium for now; could later lower some to low if readOnly
    #    or raise some to high based on other services.
    else:
        severity = severity  # explicit for readability

    normalized = {
        "source": "aws_cloudtrail",
        "category": category,
        "action": event_name,
        "actor": actor,
        "target": target,
        "severity": severity,
        "timestamp": event_time,
        # Preserve the full CloudTrail record for forensic context
        "raw": record,
    }

    return normalized


def load_cloudtrail_records(path: str) -> List[Dict[str, Any]]:
    """Load CloudTrail records from a JSON file."""
    with open(path, "r") as f:
        data = json.load(f)

    # CloudTrail files typically have a top-level "Records" list
    if isinstance(data, dict) and "Records" in data:
        return data["Records"]

    # Fallback: assume the file itself is a list of records
    if isinstance(data, list):
        return data

    raise ValueError("Unexpected CloudTrail JSON structure")


def main() -> None:
    base_dir = os.path.dirname(__file__)
    sample_path = os.path.join(base_dir, "samples", "cloudtrail_iam.json")

    print(f"Loading CloudTrail records from: {sample_path}")
    records = load_cloudtrail_records(sample_path)
    print(f"Found {len(records)} CloudTrail records")

    for i, record in enumerate(records, start=1):
        normalized = map_cloudtrail_to_normalized(record)
        print(
            f"[{i}/{len(records)}] {normalized['action']} "
            f"by {normalized['actor']} -> {normalized['target']} "
            f"(sev={normalized['severity']})"
        )
        send_event(normalized)
        time.sleep(0.2)


if __name__ == "__main__":
    main()
