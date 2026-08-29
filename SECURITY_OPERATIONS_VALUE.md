# What problem CloudSentinel solves

CloudSentinel is not a CloudTrail viewer. CloudTrail records AWS activity, but security teams still face three operational problems:

1. **Alert fatigue:** Console navigation and AWS-service activity can generate large volumes of low-value records that hide the actions an analyst needs.
2. **No context or prioritization:** A `CreateAccessKey`, a new public security-group rule, and a CloudTrail disable action are only API names until someone identifies the actor, resource, severity, likely impact, and next action.
3. **Fragmented detection:** Native AWS findings (Security Hub and GuardDuty), CloudTrail activity, and behavioral deviations normally appear in separate consoles and are investigated separately.

## CloudSentinel solution

- Builds a clean, analyst-facing activity feed while retaining all failed actions and detected threats.
- Detects deterministic security rules and behavioral deviations without opaque ML models.
- Converts related alerts into **incidents** with a 0–100 risk score, evidence list, affected actor/resource/IP, business impact, and containment actions.
- Accepts native Security Hub and GuardDuty EventBridge events at `POST /api/ingest/findings`, so AWS-managed detections and CloudSentinel detections enter one incident queue.
- Sends urgent incidents through SMTP, SNS, or signed webhook integrations.

## Interview answer

> "The problem is not lack of CloudTrail logs; AWS already provides those. The problem is that logs are high-volume, delayed in investigation, and disconnected from native findings. CloudSentinel turns raw multi-service activity into a clean, explainable incident queue. It removes repetitive AWS background traffic, correlates related evidence, detects risky behavioral changes, explains business impact, and delivers a remediation-ready alert to the security team."

## AWS integration steps

Create EventBridge rules on the default event bus for Security Hub and GuardDuty and point them to the same Lambda used for CloudTrail. Configure `BACKEND_INGEST_URL` as `/api/ingest`; the updated Lambda automatically routes Security Hub and GuardDuty events to `/api/ingest/findings` while keeping CloudTrail events on `/api/ingest`.

The backend supports Security Hub events with `detail.findings[]` and GuardDuty finding events. AWS account configuration, EventBridge rule creation, and assigning the Lambda role remain account-owner operations and are not performed by this repository.
