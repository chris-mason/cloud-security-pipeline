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

## Roadmap

### Phase 1: Telemetry Pipeline Foundation (Completed)
- [x] Set up local Splunk Enterprise instance with HTTP Event Collector (HEC)
- [x] Design a normalized security event schema for IAM activity
- [x] Implement Python-based event generator
- [x] Implement Go-based event generator
- [x] Ingest structured JSON events into Splunk
- [x] Validate field extraction and indexing
- [x] Write initial SPL analysis and detection queries

### Phase 2: Real CloudTrail Ingestion (In Progress)
- [ ] Ingest real AWS CloudTrail JSON log files
- [ ] Parse CloudTrail records and map them to the normalized schema
- [ ] Handle multiple IAM event types (CreateUser, DeleteUser, AttachPolicy, AccessKey usage)
- [ ] Preserve raw CloudTrail events for forensic context
- [ ] Compare synthetic vs. real CloudTrail telemetry in Splunk

### Phase 3: Detection Engineering
- [ ] Develop SPL detections for high-risk IAM activity
- [ ] Identify anomalous identity behavior patterns
- [ ] Implement severity-based filtering and aggregation
- [ ] Document detection logic and assumptions

### Phase 4: Cloud-Native Expansion (Future)
- [ ] Pull CloudTrail logs from S3 using AWS SDK
- [ ] Replace file-based ingestion with event-driven ingestion
- [ ] Evaluate deployment as a cloud-native service (Lambda / Cloud Run)
- [ ] Explore cross-cloud support (GCP audit logs)

### Phase 5: Hardening & Polish (Future)
- [ ] Improve error handling and retry logic
- [ ] Add basic rate limiting and batching
- [ ] Refactor configuration management
