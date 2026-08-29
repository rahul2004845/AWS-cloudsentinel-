# AWS CloudSentinel Integration Diagnostic & Fix Guide

## ❌ Why S3 Bucket Events Aren't Showing in Dashboard

### Problem Flow
```
S3 Bucket Event
    ↓
CloudTrail (may not be capturing data events)
    ↓
EventBridge Rule (may not match pattern)
    ↓
Lambda (may not trigger)
    ↓
Backend (no events received)
    ↓
Dashboard (shows 0 logs)
```

---

## 🔧 CRITICAL FIX #1: Enable CloudTrail Data Events

**Issue:** CloudTrail by default only captures **management events** (CreateBucket, DeleteBucket), NOT **data events** (PutObject, GetObject).

### Step-by-Step Fix

#### 1. Go to AWS Console → CloudTrail → Trails
1. Click on your trail (likely "management-events" or similar)
2. Go to **Data events** section
3. Click **Edit data events**

#### 2. Add S3 Data Events
- **Resource type:** S3 objects
- **S3 bucket:** Select your bucket (or use "All buckets")
- **Events:** Select
  - ✅ `Data API`
  - ✅ Read events (GetObject)
  - ✅ Write events (PutObject, DeleteObject)

#### 3. Save and Wait 5-10 Minutes
CloudTrail takes time to start logging

---

## 🔧 CRITICAL FIX #2: Verify EventBridge Rule Configuration

### Current Rule Might Be Wrong

**Check Current Pattern:**
1. AWS Console → EventBridge → Rules
2. Click `cloudsentinel-rule`
3. Check **Event pattern** section

**Current Pattern (from your setup):**
```json
{
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["signin.amazonaws.com", "iam.amazonaws.com", "s3.amazonaws.com", "ec2.amazonaws.com", "sts.amazonaws.com"]
  }
}
```

### Problem: This Pattern Might Be Too Restrictive

**✅ CORRECTED Pattern (for S3 + Security Events):**
```json
{
  "detail-type": ["AWS API Call via CloudTrail"],
  "source": ["aws.ec2", "aws.s3", "aws.iam"],
  "detail": {
    "eventSource": ["s3.amazonaws.com", "iam.amazonaws.com", "signin.amazonaws.com", "sts.amazonaws.com", "ec2.amazonaws.com"],
    "eventName": [
      "PutObject", "GetObject", "DeleteObject", "ListBuckets",
      "CreateAccessKey", "DeleteTrail", "StopLogging",
      "ConsoleLogin", "AssumeRole"
    ]
  }
}
```

### Step-by-Step to Update

1. AWS Console → **EventBridge** → **Rules**
2. Click **cloudsentinel-rule**
3. Click **Edit**
4. Scroll to **Event pattern**
5. Replace with corrected pattern above
6. Click **Update** → **Save**

---

## 🔧 CRITICAL FIX #3: Verify Lambda Configuration

### Check Lambda Environment Variable

1. AWS Console → **Lambda** → **Functions**
2. Find `cloudsentinel-ingestor`
3. Click **Configuration** tab
4. Click **Environment variables**

**✅ Must have:**
- **Key:** `BACKEND_INGEST_URL`
- **Value:** `https://zenaida-holotypic-nona.ngrok-free.dev/api/ingest`

⚠️ **IMPORTANT:** ngrok URLs expire after 8 hours of inactivity!

### Check if ngrok URL is Still Active

```powershell
# Test if ngrok URL is reachable
Invoke-WebRequest -Uri "https://zenaida-holotypic-nona.ngrok-free.dev" -UseBasicParsing

# Should NOT return 404 or "Connection refused"
# Should return 200 OK or redirect to http://localhost:8000
```

If URL is dead:
1. Restart ngrok: `ngrok http 8000`
2. Copy new URL
3. Update Lambda environment variable
4. **REDEPLOY Lambda**

---

## 🔧 CRITICAL FIX #4: Check Lambda Permissions

### Verify Lambda Can Be Invoked by EventBridge

1. Lambda Console → `cloudsentinel-ingestor`
2. **Configuration** → **Permissions**
3. Look for: `service-role/cloudsentinel-ingestor-role-XXXXX`
4. Click on role name to view in IAM

### Check Permissions Include:
- ✅ `logs:CreateLogGroup`
- ✅ `logs:CreateLogStream`
- ✅ `logs:PutLogEvents`
- ✅ Allow EventBridge to invoke (usually auto-configured)

If missing:
1. IAM Console → **Roles**
2. Find `cloudsentinel-ingestor-role`
3. Click **Add permissions** → **Create inline policy**
4. Add:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

---

## 🧪 TEST: Verify Full Pipeline

### Step 1: Check Lambda CloudWatch Logs
1. AWS Console → **CloudWatch** → **Log Groups**
2. Find `/aws/lambda/cloudsentinel-ingestor`
3. Click on latest log stream
4. Check for any errors

### Step 2: Manual Lambda Test

1. Lambda Console → `cloudsentinel-ingestor`
2. Click **Test**
3. Use test event:
```json
{
  "source": "aws.s3",
  "detail-type": "AWS API Call via CloudTrail",
  "detail": {
    "eventTime": "2026-05-02T12:00:00Z",
    "eventName": "PutObject",
    "eventSource": "s3.amazonaws.com",
    "sourceIPAddress": "192.0.2.1",
    "awsRegion": "us-east-1",
    "userIdentity": {
      "type": "IAMUser",
      "arn": "arn:aws:iam::123456789:user/testuser"
    },
    "requestParameters": {
      "bucketName": "my-bucket",
      "key": "test-file.txt"
    }
  }
}
```

4. Click **Test** button
5. Expected response:
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

### Step 3: Check Backend Received Event
1. Terminal running backend should show:
   ```
   INFO:     POST /api/ingest - 200 OK
   ```
2. Open dashboard: http://localhost:5174
3. Should show 1 log ingested

### Step 4: Create Real S3 Event
1. AWS Console → **S3** → Your Bucket
2. Upload a file
3. Wait 10 seconds
4. Check:
   - Lambda CloudWatch logs (should show invocation)
   - Backend terminal (should show POST /api/ingest)
   - Dashboard (should show 1 new log)

---

## 📋 Checklist - Complete AWS Integration

- [ ] CloudTrail enabled with **Data Events** for S3
- [ ] S3 data events configured (Read + Write)
- [ ] EventBridge rule event pattern updated
- [ ] EventBridge rule is **Enabled**
- [ ] Lambda environment variable `BACKEND_INGEST_URL` is set
- [ ] ngrok URL is active and correct
- [ ] Lambda has CloudWatch Logs permissions
- [ ] Backend is running on port 8000
- [ ] ngrok is forwarding to backend
- [ ] Frontend can reach backend at http://localhost:8000

---

## 🚨 Common Issues & Fixes

### Issue: "EventBridge rule not triggering Lambda"
**Solution:** 
- Check rule is **Enabled** (not disabled)
- Check event pattern matches your events
- Go to CloudTrail → Event history → verify events are being logged

### Issue: "Lambda returns 503 Service Unavailable"
**Solution:**
- ngrok URL expired
- Backend not running
- Run: `ngrok http 8000`
- Update Lambda env var
- Redeploy

### Issue: "Lambda returns 400 Bad Request"
**Solution:**
- Event pattern doesn't match S3 events
- Lambda code has issues
- Check CloudWatch logs: `/aws/lambda/cloudsentinel-ingestor`

### Issue: "Dashboard still shows 0 logs after fix"
**Solution:**
1. Refresh dashboard: `Ctrl+Shift+R`
2. Check backend: `curl http://localhost:8000/api/stats`
3. Check Lambda logs
4. Make sure backend is ACTUALLY running (check terminal)

---

## 🎯 Expected Behavior After Fix

```
1. Upload file to S3
   ↓ (CloudTrail captures event)
2. EventBridge rule matched
   ↓ (Rule triggers)
3. Lambda invoked
   ↓ (With environment variables)
4. Lambda sends to backend
   ↓ (POST /api/ingest)
5. Backend processes
   ↓ (Threat detection runs)
6. Data stored in mongomock
   ↓ (In-memory database)
7. Frontend queries /api/logs
   ↓ (Every 3 seconds)
8. Dashboard shows new log ✅
```

---

## 🔗 Quick AWS Links

- **CloudTrail:** https://console.aws.amazon.com/cloudtrail/
- **EventBridge Rules:** https://console.aws.amazon.com/events/home?region=us-east-1#/rules
- **Lambda Functions:** https://console.aws.amazon.com/lambda/home?region=us-east-1#/functions
- **CloudWatch Logs:** https://console.aws.amazon.com/logs/home?region=us-east-1
- **IAM Roles:** https://console.aws.amazon.com/iam/home#/roles

---

## After Applying These Fixes

1. ✅ S3 events → CloudTrail
2. ✅ CloudTrail → EventBridge
3. ✅ EventBridge → Lambda
4. ✅ Lambda → Backend
5. ✅ Backend → Dashboard

**Expected Result:** Logs appear in dashboard within 10-30 seconds of S3 action

---

**Apply these fixes and test again!** Let me know if you need help with any specific step.
