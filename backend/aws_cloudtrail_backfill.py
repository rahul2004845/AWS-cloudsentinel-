#!/usr/bin/env python3
"""
aws_cloudtrail_backfill.py

Purpose:
    Pull real AWS CloudTrail Event History logs from AWS and push them into
    the CloudSentinel backend /api/ingest endpoint.

Use this when:
    - You want to import past CloudTrail events into dashboard.
    - You want Events Monitored count to increase with real AWS logs.

Example:
    python aws_cloudtrail_backfill.py ^
      --regions ap-south-1 us-east-1 ^
      --hours 24 ^
      --limit 200 ^
      --backend-url http://localhost:8000/api/ingest

CloudShell with ngrok:
    python3 aws_cloudtrail_backfill.py \
      --regions ap-south-1 us-east-1 \
      --hours 24 \
      --limit 200 \
      --backend-url https://YOUR-NGROK-URL.ngrok-free.app/api/ingest
"""

import argparse
import datetime as dt
import json
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Iterable, List, Optional, Set

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Backfill real AWS CloudTrail Event History logs into CloudSentinel."
    )

    parser.add_argument(
        "--backend-url",
        default="http://localhost:8000/api/ingest",
        help="CloudSentinel backend ingest URL. Default: http://localhost:8000/api/ingest",
    )

    parser.add_argument(
        "--regions",
        nargs="+",
        default=["ap-south-1", "us-east-1"],
        help="AWS regions to read CloudTrail Event History from. Default: ap-south-1 us-east-1",
    )

    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="How many past hours of CloudTrail events to fetch. Default: 24",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=200,
        help="Maximum number of events to push per region. Default: 200",
    )

    parser.add_argument(
        "--profile",
        default=None,
        help="Optional AWS CLI profile name. Example: --profile cloudsecure",
    )

    parser.add_argument(
        "--api-key",
        default=None,
        help="Optional API key sent as X-API-Key header if your backend requires it.",
    )

    parser.add_argument(
        "--sleep",
        type=float,
        default=0.15,
        help="Sleep time between POST requests to backend. Default: 0.15 seconds",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and print events, but do not send to backend.",
    )

    return parser.parse_args()


def safe_json_loads(raw: str) -> Dict[str, Any]:
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return data
        return {"rawCloudTrailEvent": data}
    except Exception:
        return {"rawCloudTrailEvent": raw}


def isoformat_utc(value: Any) -> str:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        return value
    return utc_now().isoformat().replace("+00:00", "Z")


def event_source_to_eventbridge_source(event_source: str) -> str:
    """
    Converts:
        iam.amazonaws.com -> aws.iam
        ec2.amazonaws.com -> aws.ec2
        signin.amazonaws.com -> aws.signin
    """
    if not event_source:
        return "aws.unknown"

    service = event_source.split(".")[0].strip()
    if not service:
        return "aws.unknown"

    return f"aws.{service}"


def guess_detail_type(detail: Dict[str, Any]) -> str:
    event_name = detail.get("eventName", "")
    event_source = detail.get("eventSource", "")

    if event_source == "signin.amazonaws.com" or event_name == "ConsoleLogin":
        return "AWS Console Signin via CloudTrail"

    if detail.get("eventType") == "AwsServiceEvent":
        return "AWS Service Event via CloudTrail"

    return "AWS API Call via CloudTrail"


def build_eventbridge_envelope(summary_event: Dict[str, Any], region: str) -> Dict[str, Any]:
    """
    CloudTrail lookup-events returns a summary object plus CloudTrailEvent JSON string.
    This function converts it into an EventBridge-like event.

    Backend can then read event["detail"] and process real CloudTrail fields.
    """
    raw_cloudtrail = summary_event.get("CloudTrailEvent", "{}")
    detail = safe_json_loads(raw_cloudtrail)

    event_id = (
        detail.get("eventID")
        or summary_event.get("EventId")
        or summary_event.get("EventId".lower())
        or f"unknown-{time.time_ns()}"
    )

    event_time = (
        detail.get("eventTime")
        or summary_event.get("EventTime")
        or utc_now()
    )

    event_source = detail.get("eventSource") or summary_event.get("EventSource") or "unknown.amazonaws.com"
    account_id = detail.get("recipientAccountId") or detail.get("userIdentity", {}).get("accountId") or "unknown"
    aws_region = detail.get("awsRegion") or region

    envelope = {
        "version": "0",
        "id": str(event_id),
        "detail-type": guess_detail_type(detail),
        "source": event_source_to_eventbridge_source(event_source),
        "account": str(account_id),
        "time": isoformat_utc(event_time),
        "region": aws_region,
        "resources": [],
        "detail": detail,
        "_cloudsentinel_meta": {
            "ingest_method": "cloudtrail_backfill",
            "lookup_region": region,
            "pushed_at": utc_now().isoformat().replace("+00:00", "Z"),
        },
    }

    return envelope


def post_json(url: str, payload: Dict[str, Any], api_key: Optional[str] = None, timeout: int = 20) -> Dict[str, Any]:
    body = json.dumps(payload, default=str).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "CloudSentinel-CloudTrail-Backfill/1.0",
    }

    if api_key:
        headers["X-API-Key"] = api_key

    req = urllib.request.Request(
        url=url,
        data=body,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(response_body) if response_body else {}
            except Exception:
                parsed = {"raw_response": response_body}

            return {
                "ok": 200 <= response.status < 300,
                "status": response.status,
                "response": parsed,
            }

    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        return {
            "ok": False,
            "status": exc.code,
            "error": error_body,
        }

    except urllib.error.URLError as exc:
        return {
            "ok": False,
            "status": None,
            "error": str(exc),
        }


def create_session(profile: Optional[str]) -> boto3.Session:
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def lookup_cloudtrail_events(
    session: boto3.Session,
    region: str,
    start_time: dt.datetime,
    end_time: dt.datetime,
    limit: int,
) -> List[Dict[str, Any]]:
    client = session.client("cloudtrail", region_name=region)

    events: List[Dict[str, Any]] = []
    next_token: Optional[str] = None

    while len(events) < limit:
        request: Dict[str, Any] = {
            "StartTime": start_time,
            "EndTime": end_time,
            "MaxResults": min(50, limit - len(events)),
        }

        if next_token:
            request["NextToken"] = next_token

        response = client.lookup_events(**request)

        batch = response.get("Events", [])
        events.extend(batch)

        next_token = response.get("NextToken")
        if not next_token:
            break

    return events[:limit]


def get_event_identity(envelope: Dict[str, Any]) -> Dict[str, str]:
    detail = envelope.get("detail", {})
    user_identity = detail.get("userIdentity", {}) or {}

    user = (
        user_identity.get("arn")
        or user_identity.get("userName")
        or user_identity.get("principalId")
        or "unknown"
    )

    return {
        "event_id": str(detail.get("eventID") or envelope.get("id") or "unknown"),
        "event_time": str(detail.get("eventTime") or envelope.get("time") or "unknown"),
        "event_name": str(detail.get("eventName") or "unknown"),
        "event_source": str(detail.get("eventSource") or "unknown"),
        "user": str(user),
        "ip": str(detail.get("sourceIPAddress") or "unknown"),
        "region": str(detail.get("awsRegion") or envelope.get("region") or "unknown"),
    }


def main() -> int:
    args = parse_args()

    if args.hours <= 0:
        print("[ERROR] --hours must be greater than 0")
        return 2

    if args.limit <= 0:
        print("[ERROR] --limit must be greater than 0")
        return 2

    session = create_session(args.profile)

    end_time = utc_now()
    start_time = end_time - dt.timedelta(hours=args.hours)

    print("=" * 80)
    print("CloudSentinel AWS CloudTrail Backfill")
    print("=" * 80)
    print(f"Backend URL : {args.backend_url}")
    print(f"Regions     : {', '.join(args.regions)}")
    print(f"Time range  : {start_time.isoformat()} to {end_time.isoformat()}")
    print(f"Limit       : {args.limit} events per region")
    print(f"Dry run     : {args.dry_run}")
    print("=" * 80)

    total_fetched = 0
    total_sent = 0
    total_failed = 0
    seen_event_ids: Set[str] = set()

    for region in args.regions:
        print(f"\n[REGION] {region}")

        try:
            events = lookup_cloudtrail_events(
                session=session,
                region=region,
                start_time=start_time,
                end_time=end_time,
                limit=args.limit,
            )
        except (BotoCoreError, ClientError) as exc:
            print(f"[ERROR] Failed to read CloudTrail events from {region}: {exc}")
            continue

        print(f"[INFO] Fetched {len(events)} events from {region}")
        total_fetched += len(events)

        for event in events:
            envelope = build_eventbridge_envelope(event, region=region)
            identity = get_event_identity(envelope)

            event_id = identity["event_id"]
            if event_id in seen_event_ids:
                continue
            seen_event_ids.add(event_id)

            print(
                f"[EVENT] {identity['event_time']} | "
                f"{identity['event_name']} | "
                f"{identity['event_source']} | "
                f"user={identity['user']} | "
                f"ip={identity['ip']} | "
                f"region={identity['region']}"
            )

            if args.dry_run:
                continue

            result = post_json(
                url=args.backend_url,
                payload=envelope,
                api_key=args.api_key,
            )

            if result["ok"]:
                total_sent += 1
            else:
                total_failed += 1
                print(
                    f"[POST ERROR] event_id={event_id} "
                    f"status={result.get('status')} error={result.get('error')}"
                )

            if args.sleep > 0:
                time.sleep(args.sleep)

    print("\n" + "=" * 80)
    print("Backfill completed")
    print("=" * 80)
    print(f"Fetched : {total_fetched}")
    print(f"Sent    : {total_sent}")
    print(f"Failed  : {total_failed}")
    print(f"Unique  : {len(seen_event_ids)}")
    print("=" * 80)

    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())