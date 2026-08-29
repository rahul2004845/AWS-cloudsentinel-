# CloudSentinel — AWS Cloud Security Monitoring Platform

CloudSentinel is a rule-based AWS security operations platform that converts CloudTrail, GuardDuty, Security Hub, and CSPM signals into prioritized, explainable SOC incidents. It correlates cloud activity with behavioral baselines, MITRE ATT&CK mappings, risk scores, and approval-gated response actions.

## Why CloudSentinel?

AWS-native services generate valuable findings, but analysts still face noisy logs, disconnected signals, repeated alerts, and weak prioritization. CloudSentinel adds an investigation layer on top of AWS telemetry:

- Filters AWS service automation and benign operational noise.
- Builds per-identity behavioral baselines without machine learning.
- Correlates related events into risk-prioritized incidents and attack timelines.
- Connects activity, cloud exposure, and recommended containment actions in one dashboard.

## Architecture

```text
CloudTrail / GuardDuty / Security Hub
                │
           Amazon EventBridge
                │
          Amazon SQS Queue ─────► DLQ (failed deliveries)
                │
              Lambda
                │
      CloudSentinel FastAPI Backend
                │
 PostgreSQL (production) / SQLite (local development)
                │
      React SOC Dashboard + Email Alerts
```

For AWS Organizations, member accounts forward selected events through EventBridge to a central monitoring account. Events retain their AWS account ID for account-aware investigation.

## Core capabilities

- Real-time AWS activity monitoring for S3, IAM, EC2, CloudTrail, console sign-in, GuardDuty, and Security Hub.
- Rule-based UEBA: detects new IPs, unusual regions, off-hours mutations, abnormal API activity, privilege escalation, and suspicious event sequences.
- Risk-based alert prioritization with severity scoring and duplicate-safe email notification controls.
- Threat timelines, incident correlation, MITRE ATT&CK mapping, analyst case tracking, and approval-gated SOAR workflows.
- CSPM and exposure-management checks for public S3 access, weak IAM posture, encryption gaps, exposed security groups, and security-control coverage.
- SQS buffering and DLQ retention to handle ingestion bursts and prevent failed events from being silently lost.
- PostgreSQL/JSONB support for scalable production telemetry storage; SQLite remains available for local development.
- AWS Organizations multi-account inventory, central event forwarding, account allow-listing, and account-level log filtering.

## Technology stack

- Backend: Python, FastAPI, Uvicorn
- Frontend: JavaScript, React, Vite, HTML, CSS
- AWS: CloudTrail, EventBridge, Lambda, SQS, DLQ, GuardDuty, Security Hub, IAM, AWS Organizations
- Storage: PostgreSQL with JSONB for production, SQLite for local development
- Security analytics: deterministic detection rules, behavioral baselines, MITRE ATT&CK mapping, CSPM, and approval-gated SOAR

## Run locally

### Backend

```powershell
cd backend
.\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

The backend health endpoint is available at `http://localhost:8000/health`.

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

## Production configuration

Configure secrets through AWS Secrets Manager or a protected environment, never in Git:

```env
DATABASE_URL=postgresql://USER:PASSWORD@RDS_ENDPOINT:5432/cloudsentinel?sslmode=require
REQUIRE_INGEST_AUTH=true
INGEST_API_KEYS=replace-with-a-long-random-secret
ORGANIZATIONS_ENABLED=true
```

See [PRODUCTION_SCALE_DEPLOYMENT.md](PRODUCTION_SCALE_DEPLOYMENT.md) for RDS, SQS/DLQ, EventBridge, and AWS Organizations deployment instructions.

## Security note

Do not commit `.env` files, AWS access keys, SMTP passwords, database URLs, ngrok URLs, SQLite databases, or virtual environments. Use `backend/.env.example` as the safe configuration template.

## Project value

CloudSentinel is not only a dashboard for AWS findings. It reduces analyst workload by normalizing multi-source telemetry, suppressing non-actionable noise, detecting behavior deviations, prioritizing risk, and preserving an evidence trail for investigation and response.
