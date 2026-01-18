import json
import time
import os
import random
import requests

# ===== CONFIG =====
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")
INDEX = "cloud_security"

if not SPLUNK_HEC_URL:
    raise RuntimeError("SPLUNK_HEC_URL environment variable not set")

if not SPLUNK_HEC_TOKEN:
    raise RuntimeError("SPLUNK_HEC_TOKEN environment variable not set")

def send_event(event: dict) -> None:
    """Send a single event dict to Splunk HEC."""
    payload = {
        "time": int(time.time()),
        "index": INDEX,
        "event": event,
    }


    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json",
    }

    resp = requests.post(
        SPLUNK_HEC_URL,
        headers=headers,
        data=json.dumps(payload),
        verify=False,  # ok for lab; self-signed cert
    )

    print("Status:", resp.status_code, resp.text)


def generate_fake_iam_event() -> dict:
    """Create one fake IAM-style security event."""
    actions = [
        "CreateUser",
        "DeleteUser",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "CreateAccessKey",
        "DeleteAccessKey",
        "UpdateLoginProfile",
    ]

    actors = [
        "admin_user",
        "automation_role",
        "security_engineer",
        "dev_user1",
        "dev_user2",
        "unknown_user",
    ]

    targets = [
        "new_user123",
        "temporary_contractor",
        "service_account_api",
        "prod_admin",
        "test_user",
    ]

    severities = ["low", "medium", "high"]

    action = random.choice(actions)
    actor = random.choice(actors)
    target = random.choice(targets)
    severity = random.choices(
        population=severities,
        weights=[0.5, 0.3, 0.2],  # more low/medium than high
        k=1,
    )[0]

    # Small bit of “interesting” behavior: certain combos are always high severity
    if actor == "unknown_user" or action in ["DeleteUser", "CreateAccessKey"]:
        severity = "high"

    event = {
        "source": "aws_cloudtrail",
        "category": "iam",
        "action": action,
        "actor": actor,
        "target": target,
        "severity": severity,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "raw": {
            "example": "fake_iam_event",
            "event_id": random.randint(100000, 999999),
        },
    }

    return event


def main() -> None:
    num_events = 20  # how many fake events to send

    print(f"Sending {num_events} fake IAM events to Splunk...")
    for i in range(num_events):
        event = generate_fake_iam_event()
        print(f"[{i+1}/{num_events}] {event['action']} by {event['actor']} → {event['target']} (sev={event['severity']})")
        send_event(event)
        time.sleep(0.2)  # small pause so events have slightly different times


if __name__ == "__main__":
    main()
