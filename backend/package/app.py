from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from collections import Counter
from typing import Dict, Any
from mangum import Mangum

from database import logs_collection, alerts_collection
from detector import normalize_event, detect_threats

app = FastAPI(title="CloudSentinel AWS Ingestion Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

memory_logs = []
memory_alerts = []

@app.get("/")
def root():
    return {"message": "CloudSentinel backend is running on Lambda"}

@app.post("/api/ingest")
async def ingest_event(payload: Dict[str, Any]):
    event = normalize_event(payload)
    alerts = detect_threats(event)

    if logs_collection is not None:
        logs_collection.insert_one(event)
    else:
        memory_logs.append(event)

    if alerts:
        if alerts_collection is not None:
            alerts_collection.insert_many(alerts)
        else:
            memory_alerts.extend(alerts)

    return {
        "status": "success",
        "ingested": 1,
        "alerts_generated": len(alerts),
        "alerts": alerts
    }

@app.get("/api/alerts")
def get_alerts(limit: int = Query(default=50, le=200)):
    if alerts_collection is not None:
        return list(alerts_collection.find({}, {"_id": 0}).sort("timestamp", -1).limit(limit))
    return sorted(memory_alerts, key=lambda x: x["timestamp"], reverse=True)[:limit]

@app.get("/api/stats")
def get_stats():
    if alerts_collection is not None and logs_collection is not None:
        total_logs = logs_collection.count_documents({})
        total_alerts = alerts_collection.count_documents({})
        severity_docs = alerts_collection.find({}, {"_id": 0, "severity": 1})
        severity_counter = Counter(doc.get("severity", "Unknown") for doc in severity_docs)
        return {
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "severity_stats": dict(severity_counter)
        }

    severity_counter = Counter(alert.get("severity", "Unknown") for alert in memory_alerts)
    return {
        "total_logs": len(memory_logs),
        "total_alerts": len(memory_alerts),
        "severity_stats": dict(severity_counter)
    }

handler = Mangum(app, lifespan="off")