# CloudSentinel: Complete Log Dashboard Fix

## Root Cause Analysis

### 1. **Lambda Environment Variable Bug** ❌ PRIMARY ISSUE
**File:** Lambda function code  
**Line:** 5  
**Problem:**
```python
BACKEND_INGEST_URL = os.environ.get("https://zenaida-holotypic-nona.ngrok-free.dev/api/ingest")
```
Should be:
```python
BACKEND_INGEST_URL = os.environ.get("BACKEND_INGEST_URL")
```
**Impact:** Lambda fails to forward events to backend → no logs ingested → empty dashboard

---

### 2. **Frontend API Endpoint Hardcoded** ⚠️ SECONDARY ISSUE
**File:** [frontend/src/App.jsx](frontend/src/App.jsx#L27)  
**Line:** 27  
**Current:**
```javascript
const API_BASE = 'http://localhost:8000';
```

**Problem:** This works only for local development. For AWS/ngrok deployment, it should point to your actual backend URL.

---

## Fix Summary

### Step 1: Update Lambda Function (CRITICAL)

Replace the entire Lambda function with the corrected code from `backend/lambda_ingestor.py`.

Then in AWS Console:
1. Go to **Lambda** → **Functions** → `cloudsentinel-ingestor`
2. Paste the corrected code
3. Go to **Configuration** → **Environment variables**
4. Add:
   - **Key:** `BACKEND_INGEST_URL`
   - **Value:** `https://zenaida-holotypic-nona.ngrok-free.dev/api/ingest`
5. Click **Deploy**

### Step 2: Update Frontend Configuration

**Option A: For Local Development**
Backend must be running on `localhost:8000`:
```bash
cd backend
uvicorn app:app --reload --port 8000
```

**Option B: For AWS/ngrok Deployment**
Update [frontend/src/App.jsx](frontend/src/App.jsx#L27):
```javascript
// Development (local backend)
const API_BASE = process.env.VITE_API_BASE || 'http://localhost:8000';

// Or directly for ngrok:
const API_BASE = 'https://zenaida-holotypic-nona.ngrok-free.dev';
```

Then in `frontend/.env` (create if doesn't exist):
```
VITE_API_BASE=https://zenaida-holotypic-nona.ngrok-free.dev
```

### Step 3: Verify Integration

Run this test to ensure Lambda→Backend connection works:

```bash
# 1. Start backend
cd backend
uvicorn app:app --reload --port 8000

# 2. In AWS Lambda Console, test with:
{
  "detail-type": "AWS API Call via CloudTrail",
  "detail": {
    "eventName": "ConsoleLogin",
    "userIdentity": {
      "type": "IAMUser",
      "principalId": "AIDAI23HXD2O7EXAMPLE"
    },
    "sourceIPAddress": "192.0.2.1",
    "eventTime": "2026-05-02T12:00:00Z"
  }
}

# 3. Check backend logs for "Event forwarded successfully"

# 4. Start frontend
cd frontend
npm run dev

# 5. Open http://localhost:5173 and check dashboard
```

---

## Data Flow Validation Checklist

```
✓ CloudTrail Events → EventBridge Rule (cloudsentinel-rule)
✓ EventBridge → Lambda (cloudsentinel-ingestor) 
✓ Lambda has BACKEND_INGEST_URL env var set
✓ Lambda → Backend /api/ingest endpoint
✓ Backend validates & stores in MongoDB
✓ Frontend fetches from /api/logs via API_BASE
✓ Dashboard renders logs
```

---

## Debugging Commands

### Check Lambda CloudWatch Logs
```bash
aws logs tail /aws/lambda/cloudsentinel-ingestor --follow
```

### Check Backend is Receiving Events
```bash
# Monitor backend logs while Lambda is triggered
uvicorn app:app --reload --port 8000 --log-level debug
```

### Check MongoDB (if using local Mongo)
```bash
mongosh
use cloudsentinel
db.logs.find().pretty()
db.alerts.find().pretty()
```

### Check Frontend is Fetching Correctly
```
# Open browser DevTools
# Network tab → check /api/logs request
# Response tab → should show array of events
```

---

## Key Configuration Locations

| Component | File | Setting |
|-----------|------|---------|
| Lambda | AWS Console | Environment Variable: `BACKEND_INGEST_URL` |
| Frontend | [frontend/src/App.jsx](frontend/src/App.jsx#L27) | `const API_BASE = '...'` |
| Backend | [backend/app.py](backend/app.py#L31) | `@app.post("/api/ingest")` |
| EventBridge | AWS Console | Rule: `cloudsentinel-rule` |

---

## Common Issues & Solutions

### ❌ "Frontend shows empty dashboard"
- [ ] Check browser DevTools → Network tab
- [ ] Verify `/api/logs` request succeeds
- [ ] Ensure `API_BASE` points to correct backend URL
- [ ] Backend must be running and accessible

### ❌ "Lambda fails with 'Missing BACKEND_INGEST_URL'"
- [ ] Set environment variable in AWS Lambda console
- [ ] Verify value is correct ngrok URL + `/api/ingest`
- [ ] Redeploy Lambda function

### ❌ "Backend receives nothing from Lambda"
- [ ] Check EventBridge rule is **Enabled**
- [ ] Verify Lambda has EventBridge invoke permission
- [ ] Check CloudWatch logs: `/aws/lambda/cloudsentinel-ingestor`

### ❌ "ngrok URL giving 404 errors"
- [ ] ngrok tunnels expire after 8 hours
- [ ] Restart ngrok: `ngrok http 8000`
- [ ] Update `BACKEND_INGEST_URL` with new ngrok URL
- [ ] Use ngrok paid plan for persistent URLs

---

## Files Modified

- ✅ `backend/lambda_ingestor.py` - Corrected Lambda function
- ✅ `backend/LAMBDA_SETUP.md` - This setup guide
