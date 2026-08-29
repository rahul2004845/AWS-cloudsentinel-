# Low-latency AWS activity feed

The poller is now faster by default (3-second checks) and retries an event after a backend failure instead of marking it delivered prematurely. However, `LookupEvents` is a historical-query API, so decreasing the poll interval cannot guarantee immediate delivery.

Use this production path for the dashboard:

```text
CloudTrail trail -> default EventBridge event bus -> CloudSentinel Lambda -> /api/ingest -> dashboard
```

AWS documents that CloudTrail API calls are delivered to the default EventBridge bus. Write management events work with an enabled rule; read-only management events require `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`; S3 data events require that the trail explicitly logs the selected data events. [AWS EventBridge documentation](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html)

## Required configuration

1. Create a multi-region CloudTrail trail and enable logging.
2. Add S3 data-event selectors for the buckets whose object reads/writes you want in the dashboard. `GetObject` and `PutObject` are data events; Event History/`LookupEvents` only covers management events and will not provide that object-access feed. [AWS CloudTrail Event History limitations](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
3. Create an EventBridge rule on the **default** event bus with state `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` if you also want read-only console/API activity.
4. Match the following detail types: `AWS API Call via CloudTrail` and `AWS Console Signin via CloudTrail`.
5. Target the `cloudsentinel-ingestor` Lambda. Set `BACKEND_INGEST_URL` and `INGEST_API_KEY` in that Lambda.
6. Configure a dead-letter SQS queue on the EventBridge target and alarm on failed invocations.

## Clean-feed policy implemented in the backend

The dashboard retains meaningful actions such as bucket creation/deletion, bucket policy/ACL changes, object access, authentication, IAM changes, security-group changes, failed actions, and all detected threats. It suppresses repetitive console configuration reads such as `GetBucketVersioning`, `GetBucketEncryption`, `GetTrailStatus`, `DescribeTrails`, and CloudSentinel's own KMS/CloudTrail activity. Failed requests are always retained.

For audit or troubleshooting, call `GET /api/logs?include_noise=true`; the normal dashboard uses the clean feed.
