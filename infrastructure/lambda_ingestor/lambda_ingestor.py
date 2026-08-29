"""Small dependency-free EventBridge forwarder deployed by SAM.

Keep this copy limited to Lambda runtime code. The FastAPI backend's local
virtual environment and database are deliberately excluded from the artifact.
"""
import json
import os
import urllib.error
import urllib.request


BACKEND_INGEST_URL = os.environ.get("BACKEND_INGEST_URL")
INGEST_API_KEY = os.environ.get("INGEST_API_KEY", "")


def _forward(event):
    """Forward exactly one EventBridge event and raise on a retryable failure."""
    if not BACKEND_INGEST_URL:
        raise RuntimeError("Missing BACKEND_INGEST_URL environment variable")

    try:
        target_url = BACKEND_INGEST_URL.rstrip("/")
        if event.get("source") in {"aws.securityhub", "aws.guardduty"} and target_url.endswith("/api/ingest"):
            target_url += "/findings"
        request = urllib.request.Request(
            target_url,
            data=json.dumps(event).encode("utf-8"),
            headers={"Content-Type": "application/json", **({"X-API-Key": INGEST_API_KEY} if INGEST_API_KEY else {})},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = response.read().decode("utf-8")
            return {"statusCode": response.getcode(), "backend_response": json.loads(payload) if payload else {}}
    except urllib.error.HTTPError as exc:
        # Authentication/validation errors will not fix themselves. Raising still
        # preserves the evidence in the DLQ for an operator to inspect.
        raise RuntimeError(f"HTTP {exc.code} while forwarding event: {exc.read().decode('utf-8', errors='ignore')}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Connection error to backend: {exc.reason}") from exc


def lambda_handler(event, context):
    """Process direct test events and SQS batches with partial-batch retries."""
    records = event.get("Records") if isinstance(event, dict) else None
    if records and records[0].get("eventSource") == "aws:sqs":
        failures = []
        for record in records:
            try:
                _forward(json.loads(record["body"]))
            except Exception as exc:
                print(json.dumps({"level": "error", "message": "SQS record delivery failed", "messageId": record.get("messageId"), "error": str(exc)}))
                failures.append({"itemIdentifier": record["messageId"]})
        return {"batchItemFailures": failures}

    try:
        result = _forward(event)
        return {"statusCode": result["statusCode"], "body": json.dumps({"message": "Event forwarded successfully", "backend_response": result["backend_response"]})}
    except Exception as exc:
        return {"statusCode": 500, "body": json.dumps({"error": "Event forwarding failed", "details": str(exc)})}
