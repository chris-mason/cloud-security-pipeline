import json
import os
import time
from typing import Any, Dict, List

import requests


SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")
INDEX = "cloud_security"
SOURCETYPE = "json"


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
        "index": INDEX,
        "sourcetype": SOURCETYPE,
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
        verify=False,  # self-signed cert in lab
    )

    print("Status:", resp.status_code, resp.text)


def map_cloudtrail_to_normalized(record: Dict[str, Any]) -> Dict[str, Any]:
    """Map a single CloudTrail record into our normalized schema."""
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

    # Category: IAM if coming from iam.amazonaws.com, else generic
    if event_source == "iam.amazonaws.com":
        category = "iam"
    else:
        category = "cloudtrail"

    # Very simple severity mapping for now
    high_actions = {
        "DeleteUser",
        "CreateAccessKey",
        "DeleteAccessKey",
        "AttachUserPolicy",
        "PutUserPolicy",
        "UpdateLoginProfile",
    }

    if event_name in high_actions:
        severity = "high"
    elif event_name.lower().startswith("get") or event_name.lower().startswith("list"):
        severity = "low"
    else:
        severity = "medium"

    normalized = {
        "source": "aws_cloudtrail",
        "category": category,
        "action": event_name,
        "actor": actor,
        "target": target,
        "severity": severity,
        "timestamp": event_time,
        # Preserve full raw record for forensic context
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
