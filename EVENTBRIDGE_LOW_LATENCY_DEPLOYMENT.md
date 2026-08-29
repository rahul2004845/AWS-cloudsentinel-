# Low-latency EventBridge deployment

`aws_cloudtrail_live_poller.py` is useful for local demonstrations and recovery,
but `cloudtrail:LookupEvents` is Event History. AWS can make an event available
there minutes after the action, so its poll interval cannot solve a five-minute
delay.

For a near-real-time management-event feed use:

```text
AWS API action -> EventBridge default bus -> Lambda -> CloudSentinel /api/ingest -> dashboard
```

The included SAM template creates the small dependency-free Lambda package plus EventBridge rules for S3, IAM,
EC2, CloudTrail, console sign-in, GuardDuty, and Security Hub findings.

## Before deploying

1. The backend must be reachable from Lambda over **public HTTPS**. Lambda
   cannot send requests to `http://localhost:8000`. For a demo, use a temporary
   tunnel; for production use API Gateway/ALB in front of an ECS/Fargate backend.
2. Set `REQUIRE_INGEST_AUTH=true` and a long `INGEST_API_KEYS` value in the
   backend. The same key is passed to Lambda as `IngestApiKey`.
3. Enable CloudTrail. For object-level S3 telemetry, explicitly configure
   selective S3 data events for sensitive buckets; do not enable all buckets in
   a large account without evaluating volume/cost.

## Deploy with AWS SAM

From the project root:

```powershell
sam build --template-file infrastructure/eventbridge-ingestion-template.yaml
sam deploy --guided
```

When prompted:

- `BackendIngestUrl`: `https://your-api.example.com/api/ingest`
- `IngestApiKey`: the exact value from `INGEST_API_KEYS`

After deployment, create a harmless test action such as a private test S3
bucket. It should reach the dashboard without waiting for Event History.

## Operating model

- Keep the poller stopped once EventBridge ingestion is confirmed; otherwise
  both paths can see the same event. Backend event-ID deduplication prevents
  duplicate records, but disabling the fallback keeps operations simpler.
- Retain the poller only as a temporary fallback and for local demos.
- Add an SQS dead-letter queue and CloudWatch alarms before production rollout.
