#!/usr/bin/env python3
"""
aws_cloudtrail_live_poller.py

Continuously reads REAL AWS CloudTrail Event History and posts only new events
into CloudSentinel backend /api/ingest.

This fixed version:
- Does not crash when backend is slow/down or closes the connection.
- Adds HTTP timeout handling.
- Skips common AWS background/noise events by default.
- Keeps dedupe state so duplicate CloudTrail events are not posted repeatedly.

Example:
  python aws_cloudtrail_live_poller.py --regions us-east-1 ap-south-1 --poll-seconds 3 --lookback-minutes 15 --backend-url http://localhost:8000/api/ingest

If you want every AWS event, including background AWS service noise:
  python aws_cloudtrail_live_poller.py --include-noise --regions us-east-1 ap-south-1 --backend-url http://localhost:8000/api/ingest
"""

import argparse
import datetime as dt
import json
import os
import signal
import socket
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Set, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError


STOP_REQUESTED = False


def handle_stop_signal(signum, frame) -> None:
    global STOP_REQUESTED
    STOP_REQUESTED = True
    print("\n[INFO] Stop requested. Finishing current cycle...")


signal.signal(signal.SIGINT, handle_stop_signal)
signal.signal(signal.SIGTERM, handle_stop_signal)


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Continuously poll real AWS CloudTrail logs into CloudSentinel.")

    parser.add_argument(
        "--backend-url",
        default="http://localhost:8000/api/ingest",
        help="CloudSentinel backend ingest URL. Default: http://localhost:8000/api/ingest",
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        default=["us-east-1", "ap-south-1"],
        help="AWS regions to poll. Default: us-east-1 ap-south-1",
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=3,
        help="How often to poll CloudTrail. Default: 3 seconds",
    )
    parser.add_argument(
        "--lookback-minutes",
        type=int,
        default=15,
        help="Every poll checks this many previous minutes to avoid missing delayed CloudTrail events. Default: 15",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum events to fetch per region per poll cycle. Default: 100",
    )
    parser.add_argument(
        "--profile",
        default=None,
        help="Optional AWS CLI profile name. Example: --profile cloudsecure",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="Optional API key sent as X-API-Key header if backend requires it.",
    )
    parser.add_argument(
        "--state-file",
        default=".cloudsentinel_cloudtrail_seen_events.json",
        help="Local state file used to avoid duplicate posting.",
    )
    parser.add_argument(
        "--max-seen",
        type=int,
        default=10000,
        help="Maximum event IDs to keep in local dedupe state. Default: 10000",
    )
    parser.add_argument(
        "--sleep-between-posts",
        type=float,
        default=0.05,
        help="Sleep between POST requests. Default: 0.05 seconds",
    )
    parser.add_argument(
        "--post-timeout",
        type=int,
        default=10,
        help="HTTP POST timeout in seconds. Default: 10",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Read events and print them, but do not send to backend.",
    )
    parser.add_argument(
        "--include-noise",
        action="store_true",
        help="Post common background AWS noise events too. Default behavior skips noise.",
    )

    return parser.parse_args()


def safe_json_loads(raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if raw is None:
        return {}
    try:
        data = json.loads(str(raw))
        
        if isinstance(data, dict):
            return data
        return {"rawCloudTrailEvent": data}
    except Exception:
        return {"rawCloudTrailEvent": str(raw)}


def isoformat_utc(value: Any) -> str:
    if isinstance(value, dt.datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=dt.timezone.utc)
        return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        return value
    return utc_now().isoformat().replace("+00:00", "Z")


def event_source_to_eventbridge_source(event_source: str) -> str:
    if not event_source:
        return "aws.unknown"
    service = event_source.split(".")[0].strip()
    return f"aws.{service}" if service else "aws.unknown"


def guess_detail_type(detail: Dict[str, Any]) -> str:
    event_name = detail.get("eventName", "")
    event_source = detail.get("eventSource", "")
    if event_source == "signin.amazonaws.com" or event_name == "ConsoleLogin":
        return "AWS Console Signin via CloudTrail"
    if detail.get("eventType") == "AwsServiceEvent":
        return "AWS Service Event via CloudTrail"
    return "AWS API Call via CloudTrail"


def build_eventbridge_envelope(summary_event: Dict[str, Any], region: str) -> Dict[str, Any]:
    raw_cloudtrail = summary_event.get("CloudTrailEvent", "{}")
    detail = safe_json_loads(raw_cloudtrail)

    event_id = detail.get("eventID") or summary_event.get("EventId") or f"unknown-{time.time_ns()}"
    event_time = detail.get("eventTime") or summary_event.get("EventTime") or utc_now()
    event_source = detail.get("eventSource") or summary_event.get("EventSource") or "unknown.amazonaws.com"
    account_id = detail.get("recipientAccountId") or detail.get("userIdentity", {}).get("accountId") or "unknown"
    aws_region = detail.get("awsRegion") or region

    return {
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
            "ingest_method": "cloudtrail_live_poller",
            "lookup_region": region,
            "pushed_at": utc_now().isoformat().replace("+00:00", "Z"),
        },
    }


def get_event_identity(envelope: Dict[str, Any]) -> Dict[str, str]:
    detail = envelope.get("detail", {}) or {}
    user_identity = detail.get("userIdentity", {}) or {}

    if isinstance(user_identity, dict):
        user = user_identity.get("arn") or user_identity.get("userName") or user_identity.get("principalId") or "unknown"
    else:
        user = "unknown"

    return {
        "event_id": str(detail.get("eventID") or envelope.get("id") or "unknown"),
        "event_time": str(detail.get("eventTime") or envelope.get("time") or "unknown"),
        "event_name": str(detail.get("eventName") or "unknown"),
        "event_source": str(detail.get("eventSource") or "unknown"),
        "user": str(user),
        "ip": str(detail.get("sourceIPAddress") or "unknown"),
        "region": str(detail.get("awsRegion") or envelope.get("region") or "unknown"),
        "error_code": str(detail.get("errorCode") or ""),
        "user_agent": str(detail.get("userAgent") or ""),
    }


NOISE_EVENT_NAMES = {
    "DescribeAlarms",
    "DescribeAlarmHistory",
    "DescribeMetricFilters",
    "DescribeLogGroups",
    "DescribeLogStreams",
    "CreateLogStream",
    "CreateLogGroup",
    "PutLogEvents",
    "LookupEvents",
    "SendHeartBeat",
    "GetEnvironmentStatus",
    "DescribeEnvironments",
    "CreateSession",
    "DeleteSession",
    "PutCredentials",
    "RedeemCode",
    "GetCostAndUsage",
    "GetCostForecast",
    "DescribeOrganization",
    "DescribeRegisteredRegions",
    "ListManagedNotificationEvents",
    "ListNotificationHubs",
    "GetManagedNotificationEvent",
    "ListNotificationConfigurations",
    "GetBucketOwnershipControls", "GetBucketVersioning", "GetBucketPublicAccessBlock",
    "GetBucketEncryption", "GetBucketObjectLockConfiguration", "GetAccountPublicAccessBlock",
    "ListTagsForResource", "GetTrailStatus", "DescribeTrails", "ListTrails",
    "ListEventDataStores", "DescribeAvailabilityZones",
}

NOISE_SOURCES = {
    "notifications.amazonaws.com",
    "cloudshell.amazonaws.com",
    "ce.amazonaws.com",
    "organizations.amazonaws.com",
}


def is_noise_event(envelope: Dict[str, Any]) -> Tuple[bool, str]:
    detail = envelope.get("detail", {}) or {}
    event_name = str(detail.get("eventName") or "")
    event_source = str(detail.get("eventSource") or "")
    source_ip = str(detail.get("sourceIPAddress") or "")
    user_agent = str(detail.get("userAgent") or "")
    user_name = str((detail.get("userIdentity") or {}).get("userName") or (detail.get("userIdentity") or {}).get("arn") or "")

    if event_source == "securityhub.amazonaws.com" and event_name == "GetFindings":
        return True, "CloudSentinel Security Hub integration polling"

    if detail.get("errorCode"):
        return False, "failed request retained"

    # Never skip security-sensitive events even if source looks noisy.
    sensitive_events = {
        "CreateBucket", "DeleteBucket", "PutBucketPolicy", "PutBucketAcl", "PutObjectAcl",
        "CreateAccessKey", "AttachRolePolicy", "AttachUserPolicy", "AttachGroupPolicy",
        "PutRolePolicy", "PutUserPolicy", "CreateRole", "DeleteRole", "UpdateAssumeRolePolicy",
        "StopLogging", "DeleteTrail", "UpdateTrail",
        "AuthorizeSecurityGroupIngress", "RevokeSecurityGroupIngress", "RunInstances", "TerminateInstances",
        "ConsoleLogin",
    }
    if event_name in sensitive_events:
        return False, "sensitive event"

    if event_name in NOISE_EVENT_NAMES:
        return True, f"noise event name: {event_name}"

    if event_source in NOISE_SOURCES:
        return True, f"noise event source: {event_source}"

    # Frequent AWS service role assumption noise from EventBridge/Lambda.
    if event_name == "AssumeRole" and source_ip in {"events.amazonaws.com", "lambda.amazonaws.com", "cloudtrail.amazonaws.com"}:
        return True, f"service AssumeRole noise from {source_ip}"

    if event_name == "Decrypt" and "cloudsentinel" in user_name.lower():
        return True, "CloudSentinel runtime KMS decrypt activity"

    if "AWS Internal" in user_agent:
        return True, "AWS Internal userAgent"

    return False, "not noise"


def post_json(url: str, payload: Dict[str, Any], api_key: Optional[str] = None, timeout: int = 10) -> Dict[str, Any]:
    body = json.dumps(payload, default=str).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "CloudSentinel-CloudTrail-Live-Poller/2.0",
    }
    if api_key:
        headers["X-API-Key"] = api_key

    req = urllib.request.Request(url=url, data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            response_body = response.read().decode("utf-8", errors="replace")
            try:
                parsed = json.loads(response_body) if response_body else {}
            except Exception:
                parsed = {"raw_response": response_body}
            return {"ok": 200 <= response.status < 300, "status": response.status, "response": parsed}

    except urllib.error.HTTPError as exc:
        try:
            error_body = exc.read().decode("utf-8", errors="replace")
        except Exception:
            error_body = str(exc)
        return {"ok": False, "status": exc.code, "error": error_body}

    except urllib.error.URLError as exc:
        return {"ok": False, "status": None, "error": f"URL error: {exc}"}

    except (TimeoutError, socket.timeout):
        return {"ok": False, "status": None, "error": f"backend POST timed out after {timeout}s"}

    except (ConnectionResetError, BrokenPipeError) as exc:
        return {"ok": False, "status": None, "error": f"connection interrupted: {exc}"}

    except OSError as exc:
        return {"ok": False, "status": None, "error": f"network/os error: {exc}"}

    except Exception as exc:
        # Important: never let one bad POST kill the live poller.
        return {"ok": False, "status": None, "error": f"unexpected POST error: {type(exc).__name__}: {exc}"}


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


def load_seen_event_ids(state_file: str) -> List[str]:
    if not os.path.exists(state_file):
        return []
    try:
        with open(state_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        event_ids = data.get("seen_event_ids", [])
        if isinstance(event_ids, list):
            return [str(x) for x in event_ids]
    except Exception as exc:
        print(f"[WARN] Could not read state file {state_file}: {exc}")
    return []


def save_seen_event_ids(state_file: str, event_ids: List[str], max_seen: int) -> None:
    trimmed = event_ids[-max_seen:]
    data = {
        "updated_at": utc_now().isoformat().replace("+00:00", "Z"),
        "seen_event_ids": trimmed,
    }
    try:
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as exc:
        print(f"[WARN] Could not write state file {state_file}: {exc}")


def print_banner(args: argparse.Namespace) -> None:
    print("=" * 95)
    print("CloudSentinel AWS CloudTrail Live Poller - fixed timeout/noise-safe version")
    print("=" * 95)
    print(f"Backend URL        : {args.backend_url}")
    print(f"Regions            : {', '.join(args.regions)}")
    print(f"Poll every         : {args.poll_seconds} seconds")
    print(f"Lookback window    : {args.lookback_minutes} minutes")
    print(f"Limit              : {args.limit} events per region per cycle")
    print(f"POST timeout       : {args.post_timeout} seconds")
    print(f"State file         : {args.state_file}")
    print(f"Skip noise         : {not args.include_noise}")
    print(f"Dry run            : {args.dry_run}")
    print("=" * 95)


def main() -> int:
    args = parse_args()

    if args.poll_seconds <= 0:
        print("[ERROR] --poll-seconds must be greater than 0")
        return 2
    if args.lookback_minutes <= 0:
        print("[ERROR] --lookback-minutes must be greater than 0")
        return 2
    if args.limit <= 0:
        print("[ERROR] --limit must be greater than 0")
        return 2

    session = create_session(args.profile)

    seen_event_id_list = load_seen_event_ids(args.state_file)
    seen_event_ids: Set[str] = set(seen_event_id_list)

    print_banner(args)
    print(f"[INFO] Loaded {len(seen_event_ids)} previously seen event IDs")

    cycle = 0
    while not STOP_REQUESTED:
        cycle += 1
        cycle_start = utc_now()
        end_time = cycle_start
        start_time = end_time - dt.timedelta(minutes=args.lookback_minutes)

        print("\n" + "-" * 95)
        print(f"[CYCLE {cycle}] {cycle_start.isoformat().replace('+00:00', 'Z')}")
        print(f"[WINDOW] {start_time.isoformat()} to {end_time.isoformat()}")
        print("-" * 95)

        cycle_fetched = 0
        cycle_new = 0
        cycle_sent = 0
        cycle_failed = 0
        cycle_skipped_noise = 0

        for region in args.regions:
            if STOP_REQUESTED:
                break
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
            except Exception as exc:
                print(f"[ERROR] Unexpected CloudTrail lookup error from {region}: {type(exc).__name__}: {exc}")
                continue

            cycle_fetched += len(events)
            print(f"[INFO] Fetched {len(events)} events from {region}")

            # Oldest first makes dashboard ordering easier to understand.
            events.reverse()

            for event in events:
                if STOP_REQUESTED:
                    break

                envelope = build_eventbridge_envelope(event, region=region)
                identity = get_event_identity(envelope)
                event_id = identity["event_id"]

                if event_id in seen_event_ids:
                    continue

                cycle_new += 1

                is_noise, noise_reason = is_noise_event(envelope)
                if is_noise and not args.include_noise:
                    seen_event_ids.add(event_id)
                    seen_event_id_list.append(event_id)
                    cycle_skipped_noise += 1
                    print(
                        f"[SKIP-NOISE] {identity['event_time']} | {identity['event_name']} | "
                        f"{identity['event_source']} | reason={noise_reason}"
                    )
                    continue

                status = "FAILED" if identity["error_code"] else "SUCCESS"
                print(
                    f"[NEW] {identity['event_time']} | {identity['event_name']} | "
                    f"{identity['event_source']} | user={identity['user']} | "
                    f"ip={identity['ip']} | region={identity['region']} | status={status}"
                )

                if args.dry_run:
                    continue

                result = post_json(
                    url=args.backend_url,
                    payload=envelope,
                    api_key=args.api_key,
                    timeout=args.post_timeout,
                )

                if result.get("ok"):
                    cycle_sent += 1
                    seen_event_ids.add(event_id)
                    seen_event_id_list.append(event_id)
                else:
                    cycle_failed += 1
                    print(
                        f"[POST ERROR] event_id={event_id} "
                        f"status={result.get('status')} error={result.get('error')}"
                    )
                    print("[HINT] Check backend: http://localhost:8000/health and backend terminal errors.")

                if args.sleep_between_posts > 0:
                    time.sleep(args.sleep_between_posts)

        save_seen_event_ids(args.state_file, seen_event_id_list, args.max_seen)

        print("\n[CYCLE SUMMARY]")
        print(f"Fetched      : {cycle_fetched}")
        print(f"New          : {cycle_new}")
        print(f"SkippedNoise : {cycle_skipped_noise}")
        print(f"Sent         : {cycle_sent}")
        print(f"Failed       : {cycle_failed}")
        print(f"Seen DB      : {len(seen_event_ids)}")

        if STOP_REQUESTED:
            break

        print(f"\n[INFO] Sleeping {args.poll_seconds} seconds...")
        for _ in range(args.poll_seconds):
            if STOP_REQUESTED:
                break
            time.sleep(1)

    save_seen_event_ids(args.state_file, seen_event_id_list, args.max_seen)
    print("\n[INFO] Poller stopped safely.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
