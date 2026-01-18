## Problem Statement

Security teams rely on cloud audit logs (such as AWS CloudTrail) to detect identity and access misuse, 
but these logs often arrive in raw, verbose formats that are difficult to analyze consistently. 
This project demonstrates how to ingest, normalize, and analyze cloud security telemetry using a 
language-agnostic pipeline built with Python, Go, and Splunk.

## Why Python and Go?

This project intentionally uses both Python and Go to demonstrate different roles in a security pipeline:

- **Python** is used for rapid iteration, parsing, and enrichment of security events.
- **Go** is used to model high-performance collectors and agents that generate or forward telemetry at scale.

Both languages emit events using the same schema, allowing detections to remain consistent regardless of implementation.

## Data Flow

1. Python or Go generates or parses IAM-related events.
2. Events are normalized into a common security schema.
3. Events are sent over HTTPS to Splunk HTTP Event Collector (HEC).
4. Splunk indexes the events into the `cloud_security` index.
5. SPL queries are used to detect suspicious IAM activity.

## Configuration

All sensitive values (such as HEC tokens and endpoints) are externalized using environment variables.
No secrets are committed to the repository.

## How to Run (Local Lab)

1. Clone the repository:
   ```bash
   git clone https://github.com/chris-mason/cloud-security-pipeline.git

2. Set environment variables
  export SPLUNK_HEC_URL=https://<splunk-host>:8088/services/collector
  export SPLUNK_HEC_TOKEN=<your-token>

3. Run the Python Generator
  python3 python/send_event.py

4. Run the Go generator
  cd go
  go run main.go

### Detection: IAM User Creation Activity (CloudTrail)

**Goal:** Identify IAM user creation activity in AWS, grouped by the actor performing the action and the target user being created. This helps highlight bursts of identity changes or unexpected administrators creating new accounts.

**SPL:**

```spl
index=cloud_security sourcetype=aws_cloudtrail action=CreateUser
| stats count min(timestamp) as first_seen max(timestamp) as last_seen by actor target severity
| sort - count
```
### Detection: IAM User Creation Followed by Policy Attachment (10 minutes)

**Goal:** Identify potential privilege escalation by detecting when a new IAM user is created 
and then has a policy attached within a short time window.

**SPL:**

```spl
index=cloud_security sourcetype=aws_cloudtrail action IN ("CreateUser","AttachUserPolicy")
| eval event_time = strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
| sort actor target event_time
| streamstats current=f window=1 last(action) as prev_action last(event_time) as prev_time by actor target
| eval delta_seconds = event_time - prev_time
| where prev_action="CreateUser" AND action="AttachUserPolicy" AND delta_seconds <= 600
| eval minutes_between = round(delta_seconds / 60, 2)
| table _time actor target prev_action action minutes_between severity
| sort - _time
```

## Roadmap

### Phase 1: Telemetry Pipeline Foundation - Completed
- [x] Set up local Splunk Enterprise instance with HTTP Event Collector (HEC)
- [x] Design a normalized security event schema for IAM activity
- [x] Implement Python-based event generator
- [x] Implement Go-based event generator
- [x] Enforce index and sourcetype via HEC token configuration
- [x] Ingest structured JSON events into Splunk
- [x] Validate field extraction and indexing
- [x] Build ingestion, normalization, and detection dashboard panels

---

### Phase 2: Real CloudTrail Ingestion - Completed
- [x] Ingest real AWS CloudTrail-style JSON log files
- [x] Parse CloudTrail records and map them to the normalized schema
- [x] Handle multiple IAM event types  
  *(CreateUser, DeleteUser, AttachUserPolicy, CreateAccessKey, UpdateLoginProfile, ListUsers, GetUser)*
- [x] Preserve raw CloudTrail events for forensic context
- [x] Enrich severity using CloudTrail context  
  *(readOnly, managementEvent, IAM write vs read operations)*
- [x] Validate severity distribution and behavior in Splunk dashboards

---

### Phase 3: Detection Engineering - In Progress
- [x] Develop SPL detections for high-risk IAM activity  
  - IAM user creation  
  - IAM access key creation
- [x] Implement time-based correlation detection  
  *(CreateUser → AttachUserPolicy within 10 minutes)*
- [x] Build multi-panel detection dashboards in Splunk Free
- [ ] Expand detection coverage to additional IAM abuse patterns
- [ ] Document detection logic, rationale, and assumptions

---

### Phase 4: Cloud-Native Expansion - Planned
- [ ] Pull CloudTrail logs from S3 using AWS SDK
- [ ] Replace file-based ingestion with event-driven ingestion
- [ ] Evaluate deployment as a cloud-native service (Lambda / Cloud Run)
- [ ] Explore cross-cloud support (e.g., GCP audit logs)

---

### Phase 5: Hardening & Polish - Planned
- [ ] Improve error handling and retry logic
- [ ] Add batching and basic rate limiting
- [ ] Refactor configuration management (env-first, deployment-ready)
- [ ] Finalize documentation and portfolio presentation

---

### Current State Summary
At this point, the project demonstrates:
- End-to-end cloud security telemetry ingestion
- Real CloudTrail-shaped data normalization
- Context-aware severity scoring
- Single-event and multi-event IAM detections
- Practical Splunk dashboarding under a Free license
