import json
import os
import urllib.request
import urllib.error

# Correctly read the environment variable
BACKEND_INGEST_URL = os.environ.get("BACKEND_INGEST_URL")
INGEST_API_KEY = os.environ.get("INGEST_API_KEY", "")

def lambda_handler(event, context):
    """
    AWS Lambda handler to forward CloudTrail events to CloudSentinel backend.
    
    Environment variables required:
    - BACKEND_INGEST_URL: The URL of the backend ingest endpoint
    """
    
    if not BACKEND_INGEST_URL:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Missing BACKEND_INGEST_URL environment variable",
                "details": "Configure BACKEND_INGEST_URL in Lambda environment variables"
            })
        }

    try:
        body = json.dumps(event).encode("utf-8")
        # One Lambda can receive CloudTrail, Security Hub, and GuardDuty rules.
        # Native findings use the dedicated adapter endpoint; CloudTrail keeps the
        # normal activity endpoint.
        target_url = BACKEND_INGEST_URL.rstrip("/")
        if event.get("source") in {"aws.securityhub", "aws.guardduty"} and target_url.endswith("/api/ingest"):
            target_url += "/findings"

        req = urllib.request.Request(
            target_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                **({"X-API-Key": INGEST_API_KEY} if INGEST_API_KEY else {}),
            },
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=10) as response:
            response_body = response.read().decode("utf-8")
            return {
                "statusCode": response.getcode(),
                "body": json.dumps({
                    "message": "Event forwarded successfully",
                    "backend_response": json.loads(response_body) if response_body else {}
                })
            }

    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8", errors="ignore")
        return {
            "statusCode": e.code,
            "body": json.dumps({
                "error": "HTTP error while forwarding event",
                "details": error_body,
                "code": e.code
            })
        }

    except urllib.error.URLError as e:
        return {
            "statusCode": 503,
            "body": json.dumps({
                "error": "Connection error to backend",
                "details": str(e.reason)
            })
        }

    except json.JSONDecodeError as e:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Invalid JSON in response",
                "details": str(e)
            })
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": "Unexpected error",
                "details": str(e),
                "type": type(e).__name__
            })
        }
