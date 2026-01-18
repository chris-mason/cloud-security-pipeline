import json
import time
import os
import requests

SPLUNK_HEC_URL = "https://192.168.245.132:8088/services/collector"
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")
INDEX = "cloud_security"
SOURCETYPE = "json"

if not SPLUNK_HEC_TOKEN:
    raise RuntimeError("SPLUNK_HEC_TOKEN environment variable not set")

def send_event(event):
    payload = {
        "time": int(time.time()),
        "index": INDEX,
        "sourcetype": SOURCETYPE,
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
        verify=False,
    )

    print("Status:", resp.status_code, resp.text)

if __name__ == "__main__":
    event = {
        "source": "aws_cloudtrail",
        "category": "iam",
        "action": "CreateUser",
        "actor": "admin_user",
        "target": "new_user123",
        "severity": "high",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "raw": {"example": "test_event"}
    }

    send_event(event)
