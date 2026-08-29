# CloudSentinel production-scale deployment

This deployment keeps the detection engine rule-based and behavioral. It adds durable storage, queue buffering, failed-message retention, and AWS Organizations account separation.

## 1. PostgreSQL / Amazon RDS

Create a private Amazon RDS for PostgreSQL database and a least-privilege application user. Allow the CloudSentinel backend security group to reach port 5432; do not expose the database publicly. Set this value in the backend runtime environment (not in source control):

```env
DATABASE_URL=postgresql://cloudsentinel:YOUR_PASSWORD@YOUR_RDS_ENDPOINT:5432/cloudsentinel?sslmode=require
```

Install dependencies and restart the backend:

```powershell
cd backend
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8000
```

`GET /health` must report `database.mode: POSTGRESQL`. Run `backend/migrations/001_postgresql.sql` through your approved migration process before go-live; the application also initializes its core telemetry tables safely on startup.

## 2. SQS and DLQ event ingestion

The updated SAM template changes the path to **EventBridge → SQS → Lambda → CloudSentinel API**. The SQS queue absorbs bursts; a failed record is retried up to five times then retained in the DLQ for fourteen days.

```powershell
sam build --template-file infrastructure/eventbridge-ingestion-template.yaml
sam deploy --guided --template-file .aws-sam\build\template.yaml
```

Supply your public backend URL ending in `/api/ingest` and the same value configured in `INGEST_API_KEYS`. In CloudWatch, create an alarm for `ApproximateNumberOfMessagesVisible` on `cloudsentinel-ingress-dlq` greater than zero. A nonzero DLQ count means a backend/auth/network delivery failure that needs review, not data loss.

## 3. AWS Organizations multi-account monitoring

In the central monitoring account:

1. Set `ORGANIZATIONS_ENABLED=true` in the backend environment.
2. Give the backend runtime identity `organizations:ListAccounts` (management account or a delegated Organizations administrator).
3. During the central SAM deployment, provide `OrganizationId` (for example `o-abc123`). The template creates a central EventBridge bus and restricts `events:PutEvents` to that organization.
4. Deploy `infrastructure/organization-member-forwarder-template.yaml` as a CloudFormation **StackSet** to selected organization accounts and regions. Pass the central event bus ARN as `CentralEventBusArn`.
5. Optionally set `ORGANIZATION_ACCOUNT_ALLOWLIST` to the exact twelve-digit accounts that CloudSentinel may ingest.

Every normalized event already contains `account_id`; query one account with `/api/logs?account=123456789012`. The central inventory is available at `/api/organizations/accounts`.

## Operational controls

- Store `DATABASE_URL`, ingest/admin keys, and SMTP credentials in AWS Secrets Manager or Parameter Store, then inject them at runtime.
- Keep RDS backups and Multi-AZ enabled for production.
- Alert on DLQ messages, Lambda errors, queue age, backend health, and RDS connection saturation.
- Restrict CORS to the deployed dashboard and rotate ingest keys regularly.
