# CloudSentinel production integrations

CloudSentinel now uses deterministic rules plus behavioral baselines. It does not train, load, or require an ML model.

## Implemented in this repository

| Integration | Purpose | Configuration |
| --- | --- | --- |
| EventBridge / Lambda ingestion | Receive CloudTrail events in near real time | Lambda `BACKEND_INGEST_URL`, `INGEST_API_KEY` |
| CloudTrail live poller and backfill | Alternate ingestion path and historical import | `--api-key` argument |
| API-key authentication and rate limit | Protect `POST /api/ingest` | `REQUIRE_INGEST_AUTH`, `INGEST_API_KEYS`, `INGEST_RATE_LIMIT_PER_MINUTE` |
| Amazon SNS | Publish High/Critical alerts to email, SMS, AWS Chatbot, or an incident-management subscription | `SNS_ALERTS_ENABLED`, `SNS_ALERT_TOPIC_ARN` |
| Signed HTTPS webhook | Send alerts to a SIEM/SOAR, Slack relay, Teams relay, PagerDuty Events API relay, or custom incident service | `ALERT_WEBHOOK_URL`, `ALERT_WEBHOOK_SECRET` |
| SMTP email | Direct email delivery for selected severities | `EMAIL_*` variables |
| SQLite persistence | Durable single-instance/demo storage | `SQLITE_DB_PATH` |

Copy `backend/.env.example` to `backend/.env`, replace every placeholder, and keep `.env` out of source control.

## Behavioral rules now active

The backend compares each new event with retained logs before persisting it:

- New source IP on a mutating action for an identity with enough prior activity: High.
- Mutating API burst by one identity in a configurable window: High.
- Off-hours mutating action for an established identity: Medium.
- Existing behavioral rules remain: failed-login burst, S3 read-volume burst, and region change for write actions.

The thresholds are transparent environment settings in `.env.example`, so an analyst can explain and tune every alert.

## Recommended AWS production topology

```text
Organization CloudTrail (all regions, management + selected data events)
  -> EventBridge rule
  -> Lambda normalizer (least-privilege role)
  -> API Gateway + WAF + CloudSentinel service on ECS/Fargate or EKS
  -> PostgreSQL/RDS for multi-instance durable data
  -> SNS topic and/or signed webhook -> security operations tooling

EventBridge failed delivery -> SQS dead-letter queue -> replay worker
CloudTrail archive -> encrypted S3 bucket -> lifecycle policy / Athena investigations
```

Create EventBridge rules for CloudTrail management events, console sign-ins, IAM, EC2 security group, CloudTrail, and S3 data events that you intend to monitor. Configure a dead-letter SQS queue and CloudWatch alarms for Lambda errors, EventBridge failures, API 4xx/5xx, and delivery failures.

## Required production controls

- Set `REQUIRE_INGEST_AUTH=true`; send the same secret as Lambda `INGEST_API_KEY` and poller `--api-key`.
- Place the backend behind HTTPS API Gateway or an ALB; restrict inbound traffic to that layer.
- Set `CORS_ALLOW_ORIGINS` to the real dashboard origin—never `*` with credentials.
- Keep `ENABLE_DEV_ENDPOINTS=false`; the clear/resend endpoints are disabled unless explicitly enabled and authenticated with `X-Admin-Key`.
- Run the supplied `backend/Dockerfile` as a non-root user. Mount durable storage only for a single-instance SQLite deployment.
- For horizontally scaled production use PostgreSQL/RDS rather than SQLite. SQLite is intentionally retained for local/single-node use and is not a multi-replica database.
- Store API keys, webhook secrets, SMTP passwords, and database credentials in AWS Secrets Manager or SSM Parameter Store, not environment files committed to Git.
- Encrypt CloudTrail/S3/RDS at rest with KMS; use TLS in transit; enable audit retention and backups.
