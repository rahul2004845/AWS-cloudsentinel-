# CloudSentinel testing guide

Use a separate AWS test account or named test resources. Never test destructive
or exposure-changing actions against production resources.

## 1. Confirm the platform is ready

Start the backend, frontend and (for real-time AWS testing) ngrok. The dashboard
must say **LIVE AWS SECURITY FEED**. Confirm stored records with:

```powershell
Invoke-RestMethod http://localhost:8000/api/logs?limit=3 | ConvertTo-Json -Depth 4
```

For low-latency AWS management events, EventBridge/Lambda must be deployed and
the backend/ngrok tunnel must still be running. Do not also run the legacy
CloudTrail poller unless testing its fallback behavior.

## 2. Safe real-AWS tests

| Test | Action in a test account | Expected CloudSentinel result | Cleanup |
|---|---|---|---|
| S3 lifecycle | Create a private bucket with a unique test name | `CreateBucket`; **New S3 Bucket Created** (Medium) | Delete only the empty test bucket |
| IAM role | Create a role with only a minimal test policy | `CreateRole`; **IAM Role Created** (High) | Delete the test role |
| IAM key | Create an access key only for a dedicated test IAM user | `CreateAccessKey`; **IAM Access Key Created** (Critical), MITRE T1098 | Immediately deactivate/delete the key |
| Policy change | Attach `ReadOnlyAccess` to a dedicated test user/role | **IAM Privilege Change** (Critical) | Detach it |
| Network change | Add a non-public rule to an unused test security group | **Security Group Configuration Change** (Medium) | Revoke the rule |
| Console login | Log out then sign in to AWS Console with the test identity | `ConsoleLogin` visible in Live AWS Activity | None |

For every test, inspect **Live AWS Activity**, **Threats**, **Incidents**, and
**MITRE ATT&CK**. EventBridge management events normally arrive in seconds, but
there can still be short AWS delivery and dashboard-refresh delays.

## 3. Tests that need additional telemetry

| Detection | Requirement | Trigger |
|---|---|---|
| S3 object access/exfiltration | Enable selective CloudTrail S3 **data events** on a dedicated test bucket | Read 20+ test objects from the same source within 5 minutes; expected **Possible S3 Data Exfiltration** (Critical) |
| Brute-force | Do **not** repeatedly fail real AWS sign-ins | Use the local simulated event method below; five failed `ConsoleLogin` events from one IP trigger **Brute Force Attempt** |
| CloudTrail tampering | Never stop logging on a real trail | Use local simulation; `StopLogging` triggers **CloudTrail Logging Stopped** (Critical) |
| Public S3 / public SSH | Only use an isolated lab account with no workloads | CSPM finds public-access-block gaps; CloudTrail sees policy/SG changes |

## 4. Local simulated detections (safe)

These send a CloudTrail-shaped test event to your local backend. They do not
change AWS. If `REQUIRE_INGEST_AUTH=true`, enter your own ingestion key locally
where `<INGEST_KEY>` appears.

```powershell
$headers = @{ 'X-API-Key' = '<INGEST_KEY>' }
$event = @{
  eventID = [guid]::NewGuid().ToString()
  eventTime = (Get-Date).ToUniversalTime().ToString('o')
  eventName = 'CreateAccessKey'
  eventSource = 'iam.amazonaws.com'
  awsRegion = 'ap-south-1'
  sourceIPAddress = '203.0.113.10'
  userIdentity = @{ type = 'IAMUser'; userName = 'cloudsentinel-test-user'; arn = 'arn:aws:iam::557690604562:user/cloudsentinel-test-user'; accountId = '557690604562' }
  requestParameters = @{ userName = 'cloudsentinel-test-user' }
  responseElements = @{}
} | ConvertTo-Json -Depth 6

Invoke-RestMethod -Method Post http://localhost:8000/api/ingest -Headers $headers -ContentType 'application/json' -Body $event
```

Expected: **IAM Access Key Created**, Critical, MITRE T1098, incident evidence,
and email/SNS/webhook delivery if configured.

To test another rule, change only `eventName` and `eventSource`:

| eventName | eventSource | Expected alert |
|---|---|---|
| `DeleteBucket` | `s3.amazonaws.com` | S3 Bucket Deleted — High |
| `PutBucketPolicy` | `s3.amazonaws.com` | S3 Bucket Policy Modified — High |
| `StopLogging` | `cloudtrail.amazonaws.com` | CloudTrail Logging Stopped — Critical |
| `AttachUserPolicy` | `iam.amazonaws.com` | IAM Privilege Change — Critical |
| `AuthorizeSecurityGroupIngress` | `ec2.amazonaws.com` | Security Group Opened — High/Medium depending on rule details |

## 5. UEBA test

UEBA needs at least five historical events for the same IAM user. First generate
five normal low-risk events for one test user from the same region/IP. Then send
a mutating event such as `CreateAccessKey` with a new IP and Region at an
unusual hour. Review **UEBA** for the baseline, score, and reasons such as new
IP, new Region, unusual time, or new service. This remains explainable and
rule/behavior based—no ML model is required.

## 6. CSPM, Security Hub, email and SOAR

- **CSPM:** run `POST /api/cspm/scan` with `X-Admin-Key`; findings appear in
  Exposure Management. A zero-finding scan is a good result.
- **Security Hub:** enable Security Hub in the same Region and grant the backend
  `securityhub:DescribeHub` and `securityhub:GetFindings`.
- **Email:** run `POST /api/test-email`, then inspect Email Alerts for `sent`,
  `skipped`, or `failed` and the reason.
- **SOAR:** queue a response request and approve it. Keep
  `SOAR_EXECUTION_ENABLED=false` for demonstrations; this proves the approval
  workflow without changing AWS resources.

## Success criteria

Your demo is complete when one real or simulated event appears in Live AWS
Activity, creates an explainable threat, is grouped into an incident, carries a
MITRE/response recommendation where mapped, and produces a visible notification
or email delivery status.
