# Quick Start Guide - CloudSentinel

## 🚀 System is Ready!

### Access Points

| Component | URL | Purpose |
|-----------|-----|---------|
| **Frontend Dashboard** | http://localhost:5174 | View logs, alerts, stats |
| **Backend API** | http://localhost:8000 | API endpoints |
| **API Docs** | http://localhost:8000/docs | Swagger UI |

---

## 📊 Quick Test

### 1️⃣ Send Test Event (Copy & Run)

```powershell
$json = @'
{
  "detail": {
    "eventTime": "2026-05-02T12:00:00Z",
    "eventName": "ConsoleLogin",
    "eventSource": "signin.amazonaws.com",
    "sourceIPAddress": "192.0.2.1",
    "errorCode": "FailedAuthentication",
    "userIdentity": {"arn": "arn:aws:iam::123456789:user/testuser", "type": "IAMUser"},
    "awsRegion": "us-east-1"
  }
}
'@

Invoke-WebRequest -Uri "http://localhost:8000/api/ingest" -Method POST -ContentType "application/json" -Body $json -UseBasicParsing | % Content
```

### 2️⃣ View Results

- **Dashboard:** http://localhost:5174 (should show 1 alert)
- **API:** `curl http://localhost:8000/api/logs`

---

## 🔧 Restart Services

### If Backend Crashes
```powershell
cd "C:\Users\chsvr\Downloads\Cloud-Security-Monitoring-System-main (1)\Cloud-Security-Monitoring-System-main\backend"
uvicorn app:app --reload --port 8000
```

### If Frontend Crashes
```powershell
cd "C:\Users\chsvr\Downloads\Cloud-Security-Monitoring-System-main (1)\Cloud-Security-Monitoring-System-main\frontend"
npm run dev
```

---

## 🔑 Key Fixes Applied

| Issue | Fix | Status |
|-------|-----|--------|
| Lambda env var bug | Corrected to `os.environ.get("BACKEND_INGEST_URL")` | ✅ |
| Missing MongoDB | Added mongomock fallback | ✅ |
| Lost dependencies | Installed from requirements.txt | ✅ |
| No frontend access | Frontend running on 5174 | ✅ |
| Backend not responding | Now responding on 8000 | ✅ |

---

## 📝 Generate Test Logs

### Brute Force Attack (5+ failed logins)
```powershell
for ($i=1; $i -le 5; $i++) {
    $json = @"
{
  "detail": {
    "eventTime": "$(Get-Date -u -Format 'o')",
    "eventName": "ConsoleLogin",
    "errorCode": "FailedAuthentication",
    "sourceIPAddress": "10.0.0.1",
    "userIdentity": {"type": "IAMUser"}
  }
}
"@
    Invoke-WebRequest -Uri "http://localhost:8000/api/ingest" -Method POST -ContentType "application/json" -Body $json -UseBasicParsing | % Content
    Write-Host "Sent attempt $i"
}
```

### Data Exfiltration (S3 access)
```powershell
for ($i=1; $i -le 20; $i++) {
    $json = @"
{
  "detail": {
    "eventTime": "$(Get-Date -u -Format 'o')",
    "eventName": "GetObject",
    "eventSource": "s3.amazonaws.com",
    "sourceIPAddress": "10.0.0.2",
    "userIdentity": {"type": "IAMUser"}
  }
}
"@
    Invoke-WebRequest -Uri "http://localhost:8000/api/ingest" -Method POST -ContentType "application/json" -Body $json -UseBasicParsing | % Content
    Write-Host "Sent S3 request $i"
}
```

### Suspicious IAM Change
```powershell
$json = @'
{
  "detail": {
    "eventTime": "2026-05-02T12:05:00Z",
    "eventName": "CreateAccessKey",
    "eventSource": "iam.amazonaws.com",
    "sourceIPAddress": "10.0.0.3",
    "userIdentity": {"arn": "arn:aws:iam::123456789:user/admin", "type": "IAMUser"}
  }
}
'@

Invoke-WebRequest -Uri "http://localhost:8000/api/ingest" -Method POST -ContentType "application/json" -Body $json -UseBasicParsing | % Content
```

---

## 📊 Check Statistics

```powershell
Invoke-WebRequest -Uri "http://localhost:8000/api/stats" -UseBasicParsing | Select-Object -ExpandProperty Content | ConvertFrom-Json | ConvertTo-Json
```

Expected output:
```json
{
  "total_logs": 26,
  "total_alerts": 3,
  "severity_stats": {
    "High": 1,
    "Critical": 2
  }
}
```

---

## 🎯 Next: AWS Lambda Integration

Once you confirm the local system works:

1. Update Lambda function code with `backend/lambda_ingestor.py`
2. Set environment variable in Lambda console:
   ```
   BACKEND_INGEST_URL = https://your-ngrok-url/api/ingest
   ```
3. Enable EventBridge rule
4. Test with real CloudTrail events

---

## 💡 Pro Tips

- **Monitor Backend Logs:** Check terminal where uvicorn is running
- **Monitor Frontend:** Open DevTools (F12) → Console tab
- **API Documentation:** Visit http://localhost:8000/docs for interactive Swagger UI
- **Database Status:** Data persists during session; resets on backend restart

---

**All systems operational! 🎉**
