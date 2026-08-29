from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List


class CloudTrailEvent(BaseModel):
    eventVersion: Optional[str] = None
    userIdentity: Optional[Dict[str, Any]] = None
    eventTime: Optional[str] = None
    eventSource: Optional[str] = None
    eventName: Optional[str] = None
    awsRegion: Optional[str] = None
    sourceIPAddress: Optional[str] = None
    userAgent: Optional[str] = None
    errorCode: Optional[str] = None
    errorMessage: Optional[str] = None
    requestParameters: Optional[Dict[str, Any]] = None
    responseElements: Optional[Dict[str, Any]] = None
    additionalEventData: Optional[Dict[str, Any]] = None
    eventID: Optional[str] = None
    eventType: Optional[str] = None
    recipientAccountId: Optional[str] = None


class EventBridgePayload(BaseModel):
    version: Optional[str] = None
    id: Optional[str] = None
    detail_type: Optional[str] = Field(default=None, alias="detail-type")
    source: Optional[str] = None
    account: Optional[str] = None
    time: Optional[str] = None
    region: Optional[str] = None
    resources: Optional[List[str]] = None
    detail: Optional[Dict[str, Any]] = None


class AlertOut(BaseModel):
    timestamp: str
    source_ip: str
    attack_type: str
    severity: str
    description: str
    mitigation: Optional[str] = None