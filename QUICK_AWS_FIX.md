# ⚡ AWS Integration - Quick Fix Guide (5 Minutes)

## 🔴 Most Common Issue: ngrok URL Expired

ngrok free tier URLs expire after **8 hours of inactivity**. This breaks Lambda → Backend communication!

### ✅ IMMEDIATE FIX

#### Step 1: Restart ngrok
```powershell
# Kill old ngrok if running
Stop-Process -Name ngrok -Force -ErrorAction SilentlyContinue

# Start new ngrok tunnel (wait 5 seconds)
ngrok http 8000
```

**You'll see:**
```
Forwarding https://xxxxxxx-xxxx.ngrok-free.dev -> http://localhost:8000
```

Copy the new HTTPS URL.

#### Step 2: Update Lambda Environment Variable
1. AWS Console → **Lambda** → **Functions** → `cloudsentinel-ingestor`
2. **Configuration** → **Environment variables**
3. Update `BACKEND_INGEST_URL` with your **new ngrok URL + `/api/ingest`**
   - Example: `https://abc123xyz-abc.ngrok-free.dev/api/ingest`
4. Click **Save**
5. **DEPLOY** (button at top right)

#### Step 3: Test with S3 Action
1. AWS Console → **S3** → Your Bucket
2. Upload any file
3. Wait 10 seconds
4. Check:
   - Terminal with backend (should show `POST /api/ingest`)
   - Dashboard (http://localhost:5174) - should show 1 log

---

## 📋 AWS Integration Checklist

### CloudTrail Configuration
- [ ] CloudTrail is **enabled**
- [ ] **Data Events** enabled for S3
  - Go: CloudTrail → Trails → Your Trail → Data Events → Edit
  - Enable: S3 objects → Read/Write events
- [ ] CloudTrail logging S3 events (check Event History)

### EventBridge Configuration
- [ ] Rule name: `cloudsentinel-rule`
- [ ] Rule is **ENABLED** (toggle switch ON)
- [ ] **Event pattern** includes S3 events:
  ```json
  {
    "detail-type": ["AWS API Call via CloudTrail"],
    "detail": {
      "eventSource": ["s3.amazonaws.com", "iam.amazonaws.com"]
    }
  }
  ```
- [ ] **Target** is `cloudsentinel-ingestor` Lambda

### Lambda Configuration
- [ ] Function: `cloudsentinel-ingestor` deployed
- [ ] Environment variable set:
  - `BACKEND_INGEST_URL` = `https://your-ngrok-url/api/ingest`
- [ ] Has CloudWatch Logs permission
- [ ] Function code is the corrected version with proper error handling

### Local Backend
- [ ] Backend running on port 8000
- [ ] ngrok forwarding: `ngrok http 8000`
- [ ] Frontend running on port 5174

---

## 🚀 End-to-End Test (Copy & Paste)

### Test 1: Backend Responds Locally
```powershell
# This should work
Invoke-WebRequest -Uri "http://localhost:8000/api/stats" -UseBasicParsing | Select-Object -ExpandProperty Content
```

### Test 2: ngrok Forwards Correctly
```powershell
# Replace NGROK_URL with your actual URL from ngrok
$NGROK_URL = "https://zenaida-holotypic-nona.ngrok-free.dev"

Invoke-WebRequest -Uri "$NGROK_URL/api/stats" -UseBasicParsing | Select-Object -ExpandProperty Content
```

### Test 3: Lambda Works
1. AWS Lambda Console
2. Function: `cloudsentinel-ingestor`
3. Click **Test** button
4. Use test event (see below)
5. Should get HTTP 200 response

**Test Event:**
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
    "userIdentity": {"type": "IAMUser"},
    "requestParameters": {"bucketName": "my-bucket"}
  }
}
```

### Test 4: S3 Event in Dashboard
1. Upload file to S3 bucket
2. Wait 10-30 seconds
3. Open http://localhost:5174
4. Should see log appearing

---

## 🔍 Troubleshooting

### Symptom: "Dashboard shows 0 logs after S3 upload"

**Check 1: Backend Receiving Events?**
- Look at terminal where backend is running
- Should see `POST /api/ingest` on every S3 action
- If not: ngrok URL issue or EventBridge not triggering

**Check 2: EventBridge Triggering?**
- AWS Console → CloudWatch → Metrics
- Find EventBridge metrics
- Or check: CloudTrail → Event History (verify S3 events logged)

**Check 3: Lambda Executing?**
- CloudWatch → Log Groups → `/aws/lambda/cloudsentinel-ingestor`
- Check latest log stream for invocation record
- If no logs: EventBridge rule not triggering Lambda

**Check 4: Backend Reachable from Lambda?**
- Lambda CloudWatch logs should show response from backend
- If timeout (504): ngrok URL dead, need to restart ngrok + update Lambda

---

## 🎯 Most Likely Fixes Needed (In Order)

### 1️⃣ Restart ngrok (70% likely)
```powershell
ngrok http 8000
# Copy new URL, update Lambda env var
```

### 2️⃣ Enable CloudTrail Data Events (20% likely)
- CloudTrail Console → Trails → Edit
- Enable S3 data events (not just management)

### 3️⃣ Update EventBridge Pattern (5% likely)
- EventBridge Console → Rules → cloudsentinel-rule
- Ensure event pattern includes your events

### 4️⃣ Check Lambda Permissions (3% likely)
- Lambda role needs CloudWatch Logs access
- IAM → Roles → cloudsentinel-ingestor-role

### 5️⃣ Backend isn't running (2% likely)
- Terminal with uvicorn should show `Uvicorn running on http://127.0.0.1:8000`

---

## 📊 Quick Status Check

Run this PowerShell script to check everything:

```powershell
Write-Host "=== CloudSentinel Status Check ===" -ForegroundColor Cyan

# Check 1: Backend
try {
    $response = Invoke-WebRequest -Uri "http://localhost:8000/api/stats" -UseBasicParsing
    Write-Host "✅ Backend: RESPONDING" -ForegroundColor Green
} catch {
    Write-Host "❌ Backend: NOT RESPONDING (start uvicorn)" -ForegroundColor Red
}

# Check 2: Frontend
try {
    $response = Invoke-WebRequest -Uri "http://localhost:5174" -UseBasicParsing
    Write-Host "✅ Frontend: RESPONDING" -ForegroundColor Green
} catch {
    Write-Host "❌ Frontend: NOT RESPONDING (start npm run dev)" -ForegroundColor Red
}

# Check 3: ngrok
try {
    $response = Invoke-WebRequest -Uri "https://zenaida-holotypic-nona.ngrok-free.dev/api/stats" -UseBasicParsing
    Write-Host "✅ ngrok: ACTIVE" -ForegroundColor Green
} catch {
    Write-Host "⚠️  ngrok: EXPIRED or DOWN (restart ngrok)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Next: Go to AWS Console and:"
Write-Host "1. Check CloudTrail has S3 data events enabled"
Write-Host "2. Verify EventBridge rule is enabled"
Write-Host "3. Update Lambda BACKEND_INGEST_URL env var"
Write-Host "4. Test S3 upload"
```

---

## ✅ After Applying These Fixes

```
S3 Upload
    ↓
CloudTrail captures (5 seconds)
    ↓
EventBridge triggers (2 seconds)
    ↓
Lambda executes (3 seconds)
    ↓
Backend receives (1 second)
    ↓
Dashboard updates (3 seconds)
    
Total: ~15 seconds for event to appear ✅
```

---

## 🎓 Why ngrok Expires

Free ngrok URLs:
- ✅ Persist for 24 hours of continuous use
- ❌ Expire after 8 hours of inactivity
- ❌ Are random on each restart

**Solution for production:**
- Use ngrok Pro ($5/month) for persistent URLs
- Or deploy backend to AWS (EC2, Lambda, etc.)
- Or use AWS API Gateway (don't need external tunnel)

---

**Apply the fixes above and your logs should start appearing! Let me know if you need help with any step.**
