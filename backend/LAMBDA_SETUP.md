# Lambda Configuration Guide for CloudSentinel Ingestion

## Critical Fix Applied

### Bug in Original Code (Line 5)
```python
# WRONG ❌
BACKEND_INGEST_URL = os.environ.get("https://zenaida-holotypic-nona.ngrok-free.dev/api/ingest")
```

This was trying to read an environment variable **named** `"https://zenaida-holotypic-nona.ngrok-free.dev/api/ingest"`, which doesn't exist.

### Corrected Code
```python
# CORRECT ✅
BACKEND_INGEST_URL = os.environ.get("BACKEND_INGEST_URL")
```

---

## AWS Lambda Configuration Steps

### 1. Update Lambda Environment Variables

In your **Lambda function console** (`cloudsentinel-ingestor`):

1. Navigate to **Configuration** tab
2. Select **Environment variables**
3. Add a new variable:
   - **Key:** `BACKEND_INGEST_URL`
   - **Value:** `https://zenaida-holotypic-nona.ngrok-free.dev/api/ingest`
4. Click **Save**

### 2. Verify EventBridge Integration

Your EventBridge rule (`cloudsentinel-rule`) should:
- **Status:** Enabled ✓ (Already configured)
- **Event Pattern:** Captures CloudTrail events
- **Target:** Points to `cloudsentinel-ingestor` Lambda function

### 3. Test the Lambda Function

Use the AWS Lambda test panel:

```json
{
  "detail-type": "AWS API Call via CloudTrail",
  "detail": {
    "eventName": "AssumeRole",
    "userIdentity": {
      "type": "IAMUser",
      "principalId": "AIDAI23HXD2O7EXAMPLE"
    },
    "sourceIPAddress": "192.0.2.1",
    "eventTime": "2026-05-02T12:00:00Z"
  }
}
```

Expected response:
```json
{
  "statusCode": 200,
  "body": {
    "message": "Event forwarded successfully",
    "backend_response": {
      "status": "success",
      "ingested": 1,
      "alerts_generated": 0
    }
  }
}
```

---

## Troubleshooting Checklist

- [ ] `BACKEND_INGEST_URL` environment variable is set in Lambda
- [ ] ngrok URL is still active (ngrok URLs expire after ~8 hours of inactivity)
- [ ] EventBridge rule is **Enabled**
- [ ] Lambda function has permission to be invoked by EventBridge
- [ ] Backend `/api/ingest` endpoint is running and accessible
- [ ] Check Lambda CloudWatch logs for errors

### Check CloudWatch Logs

1. Navigate to **CloudWatch > Log groups**
2. Find `/aws/lambda/cloudsentinel-ingestor`
3. Review recent log streams for errors

---

## Integration Flow

```
CloudTrail Events
       ↓
EventBridge Rule (cloudsentinel-rule)
       ↓
Lambda (cloudsentinel-ingestor) - with BACKEND_INGEST_URL env var
       ↓
Backend (/api/ingest)
       ↓
Database (MongoDB)
       ↓
Frontend Dashboard (React)
```

---

## Frontend Updates

For logs to appear in the dashboard, ensure:

1. **Backend is running** and accessible via the ngrok URL
2. **Frontend is configured** to fetch from the backend:
   - Check `frontend/src/` for API endpoint configuration
   - Default endpoint should be `http://localhost:8000` for local dev
   - For production, update to match your backend URL

---

## Additional Improvements Made

✅ Added proper error handling for:
- Missing environment variables
- HTTP errors with status codes
- URL connection errors
- JSON parsing errors
- Generic exceptions

✅ Better error messages for debugging

✅ Added docstring for clarity

✅ Improved response structure for better backend integration
