#!/usr/bin/env python3
"""
AWS Cost + IAM Resource Audit  (hang-resistant version)

Key differences from the previous version:
  * Every boto3 client has short connect/read timeouts (nothing can block forever).
  * Output is flushed immediately and each discovered resource is printed live.
  * Resource inventory runs FIRST so you see resources before anything slow starts.
  * CloudTrail scans only the regions that actually hold resources (or --all-regions),
    in parallel, with a per-region time budget and page cap.
  * "AssumeRole" was removed from the CloudTrail target list (it generates thousands of
    events and was the main cause of the apparent hang; it also can't be mapped to a resource).
  * Lambda event names fixed (CloudTrail logs them as CreateFunction20150331 etc).
  * Ctrl+C no longer kills the run: whatever was collected so far is written to Excel.

Usage:
  python aws_cost_iam_audit.py -v
  python aws_cost_iam_audit.py -v --skip-cloudtrail        # fastest sanity check
  python aws_cost_iam_audit.py --debug                     # botocore request logging
"""

import argparse
import json
import logging
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import boto3
import pandas as pd
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_PROFILE = "mfa-session"
DEFAULT_REGION = "ap-south-1"
DEFAULT_DAYS = 30

VERBOSE = False
STOP = threading.Event()
_print_lock = threading.Lock()


def log(msg="", verbose_only=False):
    """Thread-safe, always-flushed print."""
    if verbose_only and not VERBOSE:
        return
    with _print_lock:
        print(msg, flush=True)


def make_config():
    return Config(
        connect_timeout=5,
        read_timeout=20,
        retries={"max_attempts": 4, "mode": "adaptive"},
    )


def get_client(session, service, region=None):
    return session.client(service, region_name=region, config=make_config())


# ============================================================
# CLOUDTRAIL EVENT CONFIGURATION
# ============================================================

# NOTE: AssumeRole intentionally removed (huge volume, not attributable to a resource).
TARGET_EVENTS = [
    "RunInstances",
    "StartInstances",
    "StopInstances",
    "TerminateInstances",
    "CreateVolume",
    "CreateDBInstance",
    "StartDBInstance",
    "StopDBInstance",
    "DeleteDBInstance",
    "CreateBucket",
    "CreateFunction20150331",
    "UpdateFunctionConfiguration20150331v2",
    "CreateCluster",
    "CreateLoadBalancer",
]

CREATION_EVENTS = {
    "EC2": {"RunInstances"},
    "EBS": {"CreateVolume"},
    "RDS": {"CreateDBInstance"},
    "S3": {"CreateBucket"},
    "Lambda": {"CreateFunction20150331", "CreateFunction"},
    "EKS": {"CreateCluster"},
    "ELB": {"CreateLoadBalancer"},
}

START_EVENTS = {
    "EC2": {"StartInstances"},
    "RDS": {"StartDBInstance"},
}

SERVICE_EVENT_SOURCES = {
    "EC2": {"ec2.amazonaws.com"},
    "EBS": {"ec2.amazonaws.com"},
    "RDS": {"rds.amazonaws.com"},
    "S3": {"s3.amazonaws.com"},
    "Lambda": {"lambda.amazonaws.com"},
    "EKS": {"eks.amazonaws.com"},
    "ELB": {"elasticloadbalancing.amazonaws.com"},
}

RESOURCE_IDENTIFIER_KEYS = {
    "EC2": {"instanceid"},
    "EBS": {"volumeid"},
    "RDS": {"dbinstanceidentifier"},
    "S3": {"bucketname"},
    "Lambda": {"functionname", "functionarn"},
    "EKS": {"name", "clustername", "clusterarn"},
    "ELB": {"loadbalancername", "loadbalancerarn"},
}


# ============================================================
# AWS SESSION
# ============================================================

def create_session(profile, region):
    session = boto3.Session(profile_name=profile, region_name=region)
    log(f"Using profile '{profile}', region '{region}'. Checking credentials...")
    identity = get_client(session, "sts", region).get_caller_identity()
    log(f"AWS Account: {identity['Account']}")
    log(f"Caller ARN:  {identity['Arn']}")
    return session, identity


# ============================================================
# COST EXPLORER
# ============================================================

def get_cost_amount(metrics):
    metric = metrics.get("UnblendedCost", {})
    return {
        "Cost": float(metric.get("Amount", 0)),
        "Currency": metric.get("Unit", "USD"),
    }


def get_cost_data(ce, start_date, end_date, granularity, group_by, sheet_name):
    rows = []
    try:
        params = {
            "TimePeriod": {"Start": start_date, "End": end_date},
            "Granularity": granularity,
            "Metrics": ["UnblendedCost"],
            "GroupBy": group_by,
        }
        page = 0
        while True:
            if STOP.is_set():
                break
            page += 1
            log(f"   {sheet_name}: requesting page {page}...", verbose_only=True)
            response = ce.get_cost_and_usage(**params)

            for period in response.get("ResultsByTime", []):
                time_period = period.get("TimePeriod", {})
                for group in period.get("Groups", []):
                    keys = group.get("Keys", [])
                    cost_info = get_cost_amount(group.get("Metrics", {}))
                    row = {
                        "Period Start": time_period.get("Start", ""),
                        "Period End": time_period.get("End", ""),
                        "Cost": cost_info["Cost"],
                        "Currency": cost_info["Currency"],
                    }
                    for index, dimension in enumerate(group_by):
                        row[dimension["Key"]] = (
                            keys[index] if index < len(keys) else "Unknown"
                        )
                    rows.append(row)

            next_token = response.get("NextPageToken")
            if not next_token:
                break
            params["NextPageToken"] = next_token

    except (ClientError, BotoCoreError) as exc:
        log(f"[ERROR] {sheet_name}: {exc}")

    log(f"   {sheet_name}: {len(rows)} rows")
    return rows


def get_service_cost(ce, start, end):
    log("\n[Cost 1/5] Service cost...")
    return get_cost_data(ce, start, end, "MONTHLY",
                         [{"Type": "DIMENSION", "Key": "SERVICE"}], "Service Cost")


def get_daily_cost(ce, start, end):
    log("[Cost 2/5] Daily cost...")
    return get_cost_data(ce, start, end, "DAILY",
                         [{"Type": "DIMENSION", "Key": "SERVICE"}], "Daily Cost")


def get_usage_breakdown(ce, start, end):
    log("[Cost 3/5] Usage breakdown...")
    return get_cost_data(
        ce, start, end, "MONTHLY",
        [{"Type": "DIMENSION", "Key": "SERVICE"},
         {"Type": "DIMENSION", "Key": "USAGE_TYPE"}],
        "Usage Breakdown")


def get_operation_breakdown(ce, start, end):
    log("[Cost 4/5] Operation breakdown...")
    return get_cost_data(
        ce, start, end, "MONTHLY",
        [{"Type": "DIMENSION", "Key": "SERVICE"},
         {"Type": "DIMENSION", "Key": "OPERATION"}],
        "Operation Breakdown")


def get_region_cost(ce, start, end):
    log("[Cost 5/5] Regional cost...")
    return get_cost_data(
        ce, start, end, "MONTHLY",
        [{"Type": "DIMENSION", "Key": "SERVICE"},
         {"Type": "DIMENSION", "Key": "REGION"}],
        "Region Breakdown")


def get_cost_forecast(ce):
    log("[Cost] Forecast...")
    rows = []
    today = datetime.now(timezone.utc).date()
    first_day_next_month = (today.replace(day=1) + timedelta(days=32)).replace(day=1)
    first_day_following_month = (first_day_next_month + timedelta(days=32)).replace(day=1)

    try:
        response = ce.get_cost_forecast(
            TimePeriod={
                "Start": first_day_next_month.isoformat(),
                "End": first_day_following_month.isoformat(),
            },
            Metric="UNBLENDED_COST",
            Granularity="MONTHLY",
        )
        for item in response.get("ForecastResultsByTime", []):
            rows.append({
                "Forecast Start": item.get("TimePeriod", {}).get("Start", ""),
                "Forecast End": item.get("TimePeriod", {}).get("End", ""),
                "Estimated Cost": float(item.get("MeanValue", 0)),
                "Currency": "USD",
                "Explanation": "AWS Cost Explorer forecast based on historical spending patterns.",
            })
    except (ClientError, BotoCoreError) as exc:
        log(f"[WARNING] Forecast unavailable: {exc}")
        rows.append({
            "Forecast Start": "", "Forecast End": "",
            "Estimated Cost": "", "Currency": "", "Explanation": str(exc),
        })
    return rows


def explain_usage(usage_rows):
    explanations = {
        "BoxUsage": "EC2 instance running hours.",
        "InstanceUsage": "Compute instance usage.",
        "EBS:VolumeUsage": "EBS storage consumption.",
        "EBS:SnapshotUsage": "EBS snapshot storage.",
        "NatGateway-Hours": "NAT Gateway running hours.",
        "NatGateway-Bytes": "NAT Gateway data processing.",
        "DataTransfer": "Data transfer charges.",
        "TimedStorage": "S3 storage consumption.",
        "Requests": "API or storage request charges.",
        "RDS:InstanceUsage": "RDS database running hours.",
        "RDS:StorageUsage": "RDS database storage.",
        "Lambda-GB-Second": "Lambda execution duration and memory.",
        "Lambda-Requests": "Lambda invocation requests.",
        "Fargate-vCPU-Hours": "Fargate vCPU consumption.",
        "Fargate-GB-Hours": "Fargate memory consumption.",
    }
    result = []
    for row in usage_rows:
        usage_type = row.get("USAGE_TYPE", "")
        explanation = "Check the AWS usage type and pricing dimension."
        for key, value in explanations.items():
            if key.lower() in usage_type.lower():
                explanation = value
                break
        result.append({
            "Service": row.get("SERVICE", ""),
            "Usage Type": usage_type,
            "Month": row.get("Period Start", ""),
            "Cost": row.get("Cost", 0),
            "Currency": row.get("Currency", ""),
            "Possible Cost Reason": explanation,
        })
    return result


# ============================================================
# RESOURCE INVENTORY  (prints every resource as it is found)
# ============================================================

def get_current_resources(session, region):
    log(f"\n[Inventory] Scanning resources in {region} ...")
    resources = []

    def add_resource(service, resource_type, resource_id, name, state,
                     created, tags=None, resource_region=None):
        tags = tags or {}
        resources.append({
            "Service": service,
            "Resource Type": resource_type,
            "Resource ID": resource_id or "",
            "Name": name or "",
            "State": state or "",
            "Created At": created or "",
            "Owner Tag": (tags.get("Owner") or tags.get("owner")
                          or tags.get("CreatedBy") or ""),
            "Environment Tag": (tags.get("Environment")
                                or tags.get("environment") or ""),
            "Region": resource_region or region,
        })
        log(f"   + {service:<7} {resource_type:<14} {resource_id or '-'}  "
            f"[{state or '-'}]  {name or ''}")

    def step(label):
        log(f"-> {label} ...")
        return time.monotonic()

    def done(label, t0, count_before):
        log(f"   {label}: {len(resources) - count_before} found "
            f"({time.monotonic() - t0:.1f}s)")

    # ---- EC2 + EBS ----
    t0, n0 = step("EC2 instances"), len(resources)
    try:
        ec2 = get_client(session, "ec2", region)
        for page in ec2.get_paginator("describe_instances").paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    tags = {i["Key"]: i["Value"] for i in instance.get("Tags", [])}
                    add_resource("EC2", "Instance", instance.get("InstanceId"),
                                 tags.get("Name", ""),
                                 instance.get("State", {}).get("Name", ""),
                                 instance.get("LaunchTime"), tags)
    except (ClientError, BotoCoreError) as exc:
        log(f"[WARNING] EC2 scan: {exc}")
    done("EC2", t0, n0)

    t0, n0 = step("EBS volumes"), len(resources)
    try:
        for page in ec2.get_paginator("describe_volumes").paginate():
            for volume in page.get("Volumes", []):
                tags = {i["Key"]: i["Value"] for i in volume.get("Tags", [])}
                add_resource("EBS", "Volume", volume.get("VolumeId"),
                             tags.get("Name", ""), volume.get("State", ""),
                             volume.get("CreateTime"), tags)
    except (ClientError, BotoCoreError, UnboundLocalError) as exc:
        log(f"[WARNING] EBS scan: {exc}")
    done("EBS", t0, n0)

    # ---- RDS ----
    t0, n0 = step("RDS instances"), len(resources)
    try:
        rds = get_client(session, "rds", region)
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page.get("DBInstances", []):
                tags = {}
                arn = db.get("DBInstanceArn")
                if arn:
                    try:
                        resp = rds.list_tags_for_resource(ResourceName=arn)
                        tags = {i["Key"]: i["Value"] for i in resp.get("TagList", [])}
                    except (ClientError, BotoCoreError) as tag_exc:
                        log(f"[WARNING] RDS tags: {tag_exc}")
                ident = db.get("DBInstanceIdentifier", "")
                add_resource("RDS", "DB Instance", ident, ident,
                             db.get("DBInstanceStatus", ""),
                             db.get("InstanceCreateTime"), tags)
    except (ClientError, BotoCoreError) as exc:
        log(f"[WARNING] RDS scan: {exc}")
    done("RDS", t0, n0)

    # ---- S3 ----
    t0, n0 = step("S3 buckets"), len(resources)
    try:
        s3_clients = {}

        def s3_for(r):
            if r not in s3_clients:
                s3_clients[r] = get_client(session, "s3", r)
            return s3_clients[r]

        buckets = s3_for(region).list_buckets().get("Buckets", [])
        log(f"   {len(buckets)} buckets listed; reading region/tags for each...")
        for bucket in buckets:
            if STOP.is_set():
                break
            name = bucket.get("Name")
            bucket_region = "us-east-1"
            try:
                loc = s3_for(region).get_bucket_location(Bucket=name).get("LocationConstraint")
                if loc:
                    bucket_region = "eu-west-1" if loc == "EU" else loc
            except (ClientError, BotoCoreError) as exc:
                log(f"[WARNING] S3 region ({name}): {exc}", verbose_only=True)

            tags = {}
            try:
                resp = s3_for(bucket_region).get_bucket_tagging(Bucket=name)
                tags = {i["Key"]: i["Value"] for i in resp.get("TagSet", [])}
            except ClientError as tag_exc:
                code = tag_exc.response.get("Error", {}).get("Code", "")
                if code not in {"NoSuchTagSet", "NoSuchTagSetError"}:
                    log(f"[WARNING] S3 tags ({name}): {code}", verbose_only=True)
            except BotoCoreError as tag_exc:
                log(f"[WARNING] S3 tags ({name}): {tag_exc}", verbose_only=True)

            add_resource("S3", "Bucket", name, name, "Active",
                         bucket.get("CreationDate"), tags, bucket_region)
    except (ClientError, BotoCoreError) as exc:
        log(f"[WARNING] S3 scan: {exc}")
    done("S3", t0, n0)

    # ---- Lambda ----
    t0, n0 = step("Lambda functions"), len(resources)
    try:
        lam = get_client(session, "lambda", region)
        for page in lam.get_paginator("list_functions").paginate():
            for fn in page.get("Functions", []):
                arn = fn.get("FunctionArn")
                tags = {}
                if arn:
                    try:
                        tags = lam.list_tags(Resource=arn).get("Tags", {})
                    except (ClientError, BotoCoreError) as tag_exc:
                        log(f"[WARNING] Lambda tags: {tag_exc}", verbose_only=True)
                add_resource("Lambda", "Function", arn, fn.get("FunctionName"),
                             fn.get("State", "Active"), fn.get("LastModified"), tags)
    except (ClientError, BotoCoreError) as exc:
        log(f"[WARNING] Lambda scan: {exc}")
    done("Lambda", t0, n0)

    # ---- EKS ----
    t0, n0 = step("EKS clusters"), len(resources)
    try:
        eks = get_client(session, "eks", region)
        for page in eks.get_paginator("list_clusters").paginate():
            for cluster_name in page.get("clusters", []):
                cluster = eks.describe_cluster(name=cluster_name)["cluster"]
                add_resource("EKS", "Cluster", cluster.get("arn"), cluster_name,
                             cluster.get("status", ""), cluster.get("createdAt"),
                             cluster.get("tags", {}))
    except (ClientError, BotoCoreError) as exc:
        log(f"[WARNING] EKS scan: {exc}")
    done("EKS", t0, n0)

    # ---- ELBv2 ----
    t0, n0 = step("Load balancers"), len(resources)
    try:
        elb = get_client(session, "elbv2", region)
        for page in elb.get_paginator("describe_load_balancers").paginate():
            for lb in page.get("LoadBalancers", []):
                arn = lb.get("LoadBalancerArn")
                tags = {}
                if arn:
                    try:
                        resp = elb.describe_tags(ResourceArns=[arn])
                        tag_list = resp.get("TagDescriptions", [])
                        if tag_list:
                            tags = {i["Key"]: i["Value"]
                                    for i in tag_list[0].get("Tags", [])}
                    except (ClientError, BotoCoreError) as tag_exc:
                        log(f"[WARNING] ELB tags: {tag_exc}", verbose_only=True)
                add_resource("ELB", "Load Balancer", arn, lb.get("LoadBalancerName"),
                             lb.get("State", {}).get("Code", ""),
                             lb.get("CreatedTime", ""), tags)
    except (ClientError, BotoCoreError) as exc:
        log(f"[WARNING] ELB scan: {exc}")
    done("ELB", t0, n0)

    # ---- Summary ----
    log(f"\n[Inventory] Total resources found: {len(resources)}")
    summary = {}
    for r in resources:
        summary[r["Service"]] = summary.get(r["Service"], 0) + 1
    for svc, cnt in sorted(summary.items()):
        log(f"   {svc:<8} {cnt}")

    return resources


# ============================================================
# CLOUDTRAIL PRINCIPAL / RESOURCE EXTRACTION
# ============================================================

def normalize_key(value):
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def extract_principal(event):
    identity = event.get("userIdentity", {})
    identity_type = identity.get("type", "Unknown")
    principal_arn = identity.get("arn", "")
    principal_id = identity.get("principalId", "")
    user_name = identity.get("userName", "")

    issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})
    issuer_arn = issuer.get("arn", "")
    issuer_name = issuer.get("userName", "")
    session_name = ""

    if identity_type == "IAMUser":
        principal_name = user_name or principal_arn.split("/")[-1]
        principal_type = "IAM User"
    elif identity_type == "AssumedRole":
        arn_parts = principal_arn.split("/")
        session_name = arn_parts[-1] if len(arn_parts) >= 3 else ""
        principal_name = issuer_name or (
            issuer_arn.split("/")[-1] if issuer_arn
            else (arn_parts[-2] if len(arn_parts) >= 2 else "Unknown Role")
        )
        principal_type = "Assumed IAM Role"
    elif identity_type == "Root":
        principal_name = "Root"
        principal_type = "Root Account"
    elif identity_type == "AWSService":
        principal_name = identity.get("invokedBy", principal_arn or "AWS Service")
        principal_type = "AWS Service"
    else:
        principal_name = user_name or principal_arn or principal_id or "Unknown"
        principal_type = identity_type

    return {
        "Principal Name": principal_name,
        "Principal Type": principal_type,
        "Principal ARN": principal_arn,
        "Principal ID": principal_id,
        "Session Issuer ARN": issuer_arn,
        "Session Issuer Name": issuer_name,
        "Session Name": session_name,
    }


def collect_service_identifiers(data, allowed_keys, values=None):
    if values is None:
        values = set()
    if isinstance(data, dict):
        for key, value in data.items():
            if (normalize_key(key) in allowed_keys
                    and isinstance(value, str) and value.strip()):
                values.add(value.strip())
            if isinstance(value, (dict, list)):
                collect_service_identifiers(value, allowed_keys, values)
    elif isinstance(data, list):
        for item in data:
            collect_service_identifiers(item, allowed_keys, values)
    return values


def detect_event_service(event):
    source = event.get("eventSource", "")
    event_name = event.get("eventName", "")
    if source == "ec2.amazonaws.com":
        return "EBS" if event_name == "CreateVolume" else "EC2"
    return {
        "rds.amazonaws.com": "RDS",
        "s3.amazonaws.com": "S3",
        "lambda.amazonaws.com": "Lambda",
        "eks.amazonaws.com": "EKS",
        "elasticloadbalancing.amazonaws.com": "ELB",
    }.get(source, "")


def extract_event_resource_keys(event, service):
    allowed_keys = RESOURCE_IDENTIFIER_KEYS.get(service, set())
    values = set()
    collect_service_identifiers(event.get("requestParameters") or {}, allowed_keys, values)
    collect_service_identifiers(event.get("responseElements") or {}, allowed_keys, values)
    for item in event.get("resources") or []:
        resource_name = item.get("resourceName")
        if isinstance(resource_name, str) and resource_name.strip():
            values.add(resource_name.strip())
    return values


def get_resource_match_keys(resource):
    service = resource.get("Service", "")
    keys = set()
    resource_id = resource.get("Resource ID")
    if resource_id:
        keys.add(str(resource_id).strip())
    if service in {"S3", "Lambda", "EKS", "ELB", "RDS"}:
        resource_name = resource.get("Name")
        if resource_name:
            keys.add(str(resource_name).strip())
    return keys


# ============================================================
# CLOUDTRAIL SCANNING (bounded, parallel across regions)
# ============================================================

def get_enabled_regions(session, fallback_region):
    try:
        response = get_client(session, "ec2", fallback_region).describe_regions(AllRegions=False)
        regions = [r["RegionName"] for r in response.get("Regions", [])]
    except (ClientError, BotoCoreError) as exc:
        log(f"[WARNING] Could not list regions: {exc}")
        regions = [fallback_region]
    return sorted(set(regions or [fallback_region]))


def parse_event(item, event_name, region):
    try:
        event = json.loads(item.get("CloudTrailEvent", "{}"))
    except (json.JSONDecodeError, TypeError):
        return None
    service = detect_event_service(event)
    principal = extract_principal(event)
    resource_keys = extract_event_resource_keys(event, service) if service else set()
    return {
        "Event Time": event.get("eventTime", item.get("EventTime")),
        "Event Name": event.get("eventName", event_name),
        "AWS Service": event.get("eventSource", ""),
        "Detected Service": service,
        "AWS Region": event.get("awsRegion", region),
        "Principal Name": principal["Principal Name"],
        "Principal Type": principal["Principal Type"],
        "Principal ARN": principal["Principal ARN"],
        "Principal ID": principal["Principal ID"],
        "Session Issuer ARN": principal["Session Issuer ARN"],
        "Session Issuer Name": principal["Session Issuer Name"],
        "Session Name": principal["Session Name"],
        "Source IP": event.get("sourceIPAddress", ""),
        "User Agent": event.get("userAgent", ""),
        "CloudTrail Event ID": event.get("eventID", item.get("EventId", "")),
        "Read Only": event.get("readOnly", ""),
        "_resource_keys": resource_keys,
    }


def scan_cloudtrail_region(client, region, start_time, end_time, budget, max_pages):
    """Scan one region. Stops when the time budget or page cap is reached."""
    rows = []
    t0 = time.monotonic()
    last_call = 0.0
    log(f"[CloudTrail] {region}: started (budget {budget}s)")

    for event_name in TARGET_EVENTS:
        if STOP.is_set():
            break
        if time.monotonic() - t0 > budget:
            log(f"[CloudTrail] {region}: time budget reached, skipping remaining events")
            break

        token, pages, count = None, 0, 0
        while pages < max_pages:
            if STOP.is_set() or time.monotonic() - t0 > budget:
                break

            # LookupEvents is limited to ~2 requests/sec per region
            wait = 0.6 - (time.monotonic() - last_call)
            if wait > 0:
                time.sleep(wait)

            kwargs = {
                "LookupAttributes": [{"AttributeKey": "EventName",
                                      "AttributeValue": event_name}],
                "StartTime": start_time,
                "EndTime": end_time,
                "MaxResults": 50,
            }
            if token:
                kwargs["NextToken"] = token

            try:
                resp = client.lookup_events(**kwargs)
            except (ClientError, BotoCoreError) as exc:
                log(f"[WARNING] CloudTrail {region} {event_name}: {exc}")
                break
            last_call = time.monotonic()
            pages += 1

            for item in resp.get("Events", []):
                parsed = parse_event(item, event_name, region)
                if parsed:
                    rows.append(parsed)
                    count += 1

            token = resp.get("NextToken")
            if not token:
                break

        if pages >= max_pages and token:
            log(f"[WARNING] CloudTrail {region} {event_name}: page cap hit "
                f"({max_pages}); results truncated")
        log(f"   [{region}] {event_name}: {count} events ({pages} pages)",
            verbose_only=True)

    log(f"[CloudTrail] {region}: done, {len(rows)} events in {time.monotonic() - t0:.0f}s")
    return rows


def get_cloudtrail_activity(session, regions, days, budget, workers, max_pages):
    log(f"\n[CloudTrail] Scanning {len(regions)} region(s): {', '.join(regions)}")
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=days)

    # Clients are created on the main thread (Session is not thread-safe)
    clients = {r: get_client(session, "cloudtrail", r) for r in regions}

    all_events = []
    executor = ThreadPoolExecutor(max_workers=max(1, workers))
    futures = {
        executor.submit(scan_cloudtrail_region, clients[r], r, start_time,
                        end_time, budget, max_pages): r
        for r in regions
    }
    try:
        for fut in as_completed(futures):
            try:
                all_events.extend(fut.result())
            except Exception as exc:  # keep going if one region fails
                log(f"[WARNING] CloudTrail {futures[fut]} failed: {exc}")
    except KeyboardInterrupt:
        log("\n[Interrupted] Stopping CloudTrail scan; using events collected so far...")
        STOP.set()
        for fut in futures:
            if fut.done() and not fut.cancelled():
                try:
                    all_events.extend(fut.result())
                except Exception:
                    pass
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    log(f"[CloudTrail] Total events collected: {len(all_events)}")
    return all_events


# ============================================================
# IAM RESOURCE ATTRIBUTION
# ============================================================

def extract_principal_from_row(event):
    if not event:
        return {}
    return {
        "Principal Name": event.get("Principal Name", "Unknown"),
        "Principal Type": event.get("Principal Type", "Unknown"),
        "Principal ARN": event.get("Principal ARN", ""),
        "Session Issuer ARN": event.get("Session Issuer ARN", ""),
        "Session Name": event.get("Session Name", ""),
    }


def attribute_resources(resources, cloudtrail_events):
    log("\n[Attribution] Mapping IAM activity to resources...")

    attribution_rows, timeline_rows, unidentified_rows = [], [], []

    # index events by service for speed
    events_by_service = {}
    for ev in cloudtrail_events:
        events_by_service.setdefault(ev.get("Detected Service"), []).append(ev)

    for resource in resources:
        service = resource.get("Service", "")
        resource_id = str(resource.get("Resource ID") or "").strip()
        resource_keys = get_resource_match_keys(resource)
        resource_region = resource.get("Region", "")

        matched_events = []
        for event in events_by_service.get(service, []):
            if event.get("AWS Service") not in SERVICE_EVENT_SOURCES.get(service, set()):
                continue
            event_region = event.get("AWS Region", "")
            if resource_region and event_region and resource_region != event_region:
                continue
            if resource_keys.intersection(event.get("_resource_keys", set())):
                matched_events.append(event)

        matched_events.sort(key=lambda item: str(item.get("Event Time", "")))

        creation_names = CREATION_EVENTS.get(service, set())
        start_names = START_EVENTS.get(service, set())

        creation_events = [e for e in matched_events if e.get("Event Name") in creation_names]
        start_events = [e for e in matched_events if e.get("Event Name") in start_names]

        creator_event = creation_events[0] if creation_events else None
        starter_event = start_events[-1] if start_events else None
        latest_event = matched_events[-1] if matched_events else None

        creator = extract_principal_from_row(creator_event)
        starter = extract_principal_from_row(starter_event)
        latest = extract_principal_from_row(latest_event)

        created_at = (creator_event.get("Event Time") if creator_event
                      else resource.get("Created At", ""))

        if creator_event:
            status = "Creator Identified"
        elif matched_events:
            status = "Activity Found - Creator Not Confirmed"
        else:
            status = "No Matching CloudTrail Event"

        attribution_rows.append({
            "Service": service,
            "Resource Type": resource.get("Resource Type", ""),
            "Resource ID": resource_id,
            "Resource Name": resource.get("Name", ""),
            "Region": resource_region,
            "Current State": resource.get("State", ""),
            "Created By": creator.get("Principal Name", "Unknown"),
            "Principal Type": creator.get("Principal Type", "Unknown"),
            "Creator ARN": creator.get("Principal ARN", ""),
            "Creator Role ARN": creator.get("Session Issuer ARN", ""),
            "Creator Session Name": creator.get("Session Name", ""),
            "Created At": created_at,
            "Creation Event": creator_event.get("Event Name", "") if creator_event else "",
            "Started By": starter.get("Principal Name", "Unknown") if starter_event else "N/A",
            "Starter Principal Type": starter.get("Principal Type", "") if starter_event else "",
            "Starter ARN": starter.get("Principal ARN", "") if starter_event else "",
            "Started At": starter_event.get("Event Time", "") if starter_event else "",
            "Latest Activity By": latest.get("Principal Name", "Unknown"),
            "Latest Activity": latest_event.get("Event Name", "") if latest_event else "",
            "Latest Activity Time": latest_event.get("Event Time", "") if latest_event else "",
            "Matched CloudTrail Events": len(matched_events),
            "Attribution Status": status,
            "Cost Attribution": "Not directly available from Cost Explorer",
        })

        if not creator_event:
            if matched_events:
                reason = ("Related activity was found, but no matching creation event "
                          "was found in the selected CloudTrail period.")
            else:
                reason = ("No exact service-specific resource identifier match was found. "
                          "The resource may predate the lookback period, belong to another "
                          "account, or use an event not included in the targeted event list.")
            unidentified_rows.append({
                "Service": service,
                "Resource Type": resource.get("Resource Type", ""),
                "Resource ID": resource_id,
                "Resource Name": resource.get("Name", ""),
                "Region": resource_region,
                "Matched Events": len(matched_events),
                "Reason": reason,
            })

    for event in cloudtrail_events:
        timeline_rows.append({k: v for k, v in event.items() if not k.startswith("_")})

    identified = sum(1 for r in attribution_rows if r["Attribution Status"] == "Creator Identified")
    log(f"[Attribution] Confirmed creators: {identified}/{len(resources)}")
    log(f"[Attribution] Unidentified resources: {len(unidentified_rows)}")
    return attribution_rows, timeline_rows, unidentified_rows


# ============================================================
# KIRO DIAGNOSTIC
# ============================================================

def kiro_diagnostic(session, identity, region):
    log("\n[Kiro] Checking identity information...")
    rows = [
        {"Check": "Current AWS Identity", "Result": identity.get("Arn", ""),
         "Status": "Retrieved",
         "Explanation": "Identifies the AWS credentials used by this script. "
                        "It does not prove Kiro subscription assignment."},
        {"Check": "AWS Account", "Result": identity.get("Account", ""),
         "Status": "Retrieved",
         "Explanation": "AWS account associated with current credentials."},
    ]
    try:
        sso = get_client(session, "sso-admin", region)
        instances = sso.list_instances().get("Instances", [])
        if instances:
            for inst in instances:
                rows.append({
                    "Check": "Identity Center Instance",
                    "Result": inst.get("InstanceArn", ""),
                    "Status": "Visible",
                    "Explanation": "Identity Center instance is visible. "
                                   "This does not confirm Kiro seat assignment."})
        else:
            rows.append({
                "Check": "Identity Center Instance",
                "Result": "No instance returned", "Status": "Not Found",
                "Explanation": "No Identity Center instance was returned in this "
                               "account and region context."})
    except (ClientError, BotoCoreError) as exc:
        rows.append({
            "Check": "Identity Center Visibility", "Result": str(exc),
            "Status": "Unavailable",
            "Explanation": "The script could not verify Identity Center visibility."})

    rows.append({
        "Check": "Kiro Subscription Assignment",
        "Result": "Manual admin-console verification required",
        "Status": "Not Verified",
        "Explanation": "This script cannot conclusively verify Kiro seat assignment. "
                       "Check Kiro Users & Groups > Subscriptions, user identity, "
                       "subscription status and organization settings."})
    return rows


def get_missing_owner_tags(resources):
    rows = []
    for r in resources:
        if not r.get("Owner Tag"):
            rows.append({
                "Service": r.get("Service"),
                "Resource Type": r.get("Resource Type"),
                "Resource ID": r.get("Resource ID"),
                "Name": r.get("Name"),
                "Region": r.get("Region"),
                "Issue": "Owner tag missing",
                "Explanation": "Resource creator cannot be reliably identified "
                               "from current resource tags.",
            })
    return rows


# ============================================================
# FINAL SUMMARY (cost + region + status + IAM owner)
# ============================================================

ACTIVE_STATES = {
    "running", "available", "in-use", "in_use", "active", "creating", "pending",
    "starting", "modifying", "backing-up", "provisioning", "configuring-enhanced-monitoring",
    "storage-optimization", "upgrading", "rebooting",
}
INACTIVE_STATES = {
    "stopped", "stopping", "terminated", "shutting-down", "deleted", "deleting",
    "failed", "inactive", "error", "deleted-by-aws",
}

# Cost Explorer service name (substring, lowercase) -> inventory service(s)
COST_TO_INVENTORY = [
    ("ec2 - other", ["EC2", "EBS"]),
    ("elastic compute cloud", ["EC2"]),
    ("simple storage service", ["S3"]),
    ("relational database", ["RDS"]),
    ("lambda", ["Lambda"]),
    ("kubernetes", ["EKS"]),
    ("elastic load balancing", ["ELB"]),
]


def inventory_services_for(cost_service):
    name = (cost_service or "").lower()
    for needle, services in COST_TO_INVENTORY:
        if needle in name:
            return services
    return []


def principal_label(name, ptype, session=""):
    if not name or name in {"Unknown", "N/A"}:
        return ""
    label = f"{name} ({ptype})" if ptype else name
    if session and ptype == "Assumed IAM Role":
        label = f"{name}/{session} ({ptype})"
    return label


def build_final_summary(region_cost, resources, iam_attribution, cloudtrail_ran):
    """One row per (Service, Region): cost, status, resource states, IAM owner."""
    log("\n[Summary] Building final summary sheet...")

    attr_by_resource = {}
    for a in iam_attribution:
        attr_by_resource[(a.get("Service"), a.get("Resource ID"), a.get("Region"))] = a

    months = sorted({r.get("Period Start", "")[:7] for r in region_cost if r.get("Period Start")})

    # cost grouped by (service, region)
    groups = {}
    for r in region_cost:
        key = (r.get("SERVICE", ""), r.get("REGION", ""))
        g = groups.setdefault(key, {"total": 0.0, "months": {}})
        g["total"] += r.get("Cost", 0) or 0
        m = (r.get("Period Start", "") or "")[:7]
        g["months"][m] = g["months"].get(m, 0) + (r.get("Cost", 0) or 0)

    covered = set()  # (inventory service, region) already attached to a cost row
    rows = []

    def summarize(service_label, region, cost_info, matched):
        states = {}
        for res in matched:
            st = (res.get("State") or "unknown").lower()
            states[st] = states.get(st, 0) + 1
        active = sum(c for s, c in states.items() if s in ACTIVE_STATES)
        inactive = sum(c for s, c in states.items() if s in INACTIVE_STATES)

        if not matched:
            status = "No Resources Found"
            note = ("No tracked resource in this service/region. Charge is usage-based, "
                    "already deleted, or the service is not covered by the inventory.")
        elif active and not inactive:
            status, note = "Active", "All tracked resources are in an active state."
        elif active and inactive:
            status, note = "Partially Active", "Some resources are active, some stopped/inactive."
        elif inactive and not active:
            status, note = "Inactive", "All tracked resources are stopped/inactive (storage may still be billed)."
        else:
            status, note = "Unknown", "Resource states could not be classified."

        creators, starters, latest, arns = [], [], [], []
        for res in matched:
            a = attr_by_resource.get((res.get("Service"), res.get("Resource ID"), res.get("Region")), {})
            c = principal_label(a.get("Created By"), a.get("Principal Type"), a.get("Creator Session Name", ""))
            s = principal_label(a.get("Started By"), a.get("Starter Principal Type"))
            l = principal_label(a.get("Latest Activity By"), "")
            for lst, val in ((creators, c), (starters, s), (latest, l)):
                if val and val not in lst:
                    lst.append(val)
            arn = a.get("Creator Role ARN") or a.get("Creator ARN")
            if arn and arn not in arns:
                arns.append(arn)
            tag = res.get("Owner Tag")
            if tag and f"tag:{tag}" not in creators and not c:
                creators.append(f"tag:{tag}")

        if matched and not creators:
            creators_text = ("Not identified (CloudTrail skipped)" if not cloudtrail_ran
                             else "Not identified (created before lookback window)")
        elif not matched:
            creators_text = "N/A (no tracked resources)"
        else:
            creators_text = "; ".join(creators)

        row = {
            "Service": service_label,
            "Region": region,
            "Service Status": status,
            "Status Note": note,
            "Total Cost (USD)": round(cost_info["total"], 6),
        }
        for m in months:
            row[f"{m} Cost (USD)"] = round(cost_info["months"].get(m, 0), 6)
        row.update({
            "Resources Found": len(matched),
            "Active Resources": active,
            "Inactive Resources": inactive,
            "Resource States": ", ".join(f"{s}: {c}" for s, c in sorted(states.items())) or "-",
            "Resource IDs": "; ".join(str(r.get("Name") or r.get("Resource ID")) for r in matched[:15])
                            + (" ..." if len(matched) > 15 else ""),
            "Created By (IAM User / Role)": creators_text,
            "Started By (IAM User / Role)": "; ".join(starters) if starters else "N/A",
            "Latest Activity By": "; ".join(latest) if latest else "N/A",
            "IAM Role / Principal ARN": "; ".join(arns) if arns else "",
        })
        return row

    for (service, region), cost_info in groups.items():
        inv_services = inventory_services_for(service)
        matched = [r for r in resources
                   if r.get("Service") in inv_services and r.get("Region") == region]
        for s in inv_services:
            covered.add((s, region))
        rows.append(summarize(service, region, cost_info, matched))

    # resources that exist but have no cost row (free tier / $0 omitted)
    leftovers = {}
    for res in resources:
        if (res.get("Service"), res.get("Region")) not in covered:
            leftovers.setdefault((res.get("Service"), res.get("Region")), []).append(res)
    for (service, region), matched in leftovers.items():
        rows.append(summarize(f"{service} (inventory only)", region,
                              {"total": 0.0, "months": {}}, matched))

    rows.sort(key=lambda r: r["Total Cost (USD)"], reverse=True)  # default: high -> low
    log(f"[Summary] {len(rows)} rows (sorted high to low by cost; "
        f"use the header filter in Excel to change)")
    return rows


# ============================================================
# EXCEL REPORT
# ============================================================

def clean_datetime(value):
    if isinstance(value, pd.Timestamp):
        if value.tzinfo is not None:
            return value.tz_localize(None)
    elif isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.replace(tzinfo=None)
    return value


def generate_report(output, sheets):
    log("\n[Report] Generating Excel report...")

    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        for sheet_name, data in sheets:
            df = pd.DataFrame(data)
            if df.empty:
                df = pd.DataFrame({"Information": ["No data returned or access unavailable."]})
            df = df.apply(lambda column: column.map(clean_datetime))
            df.to_excel(writer, sheet_name=sheet_name[:31], index=False)
            log(f"   sheet: {sheet_name} ({len(data)} rows)")

        for worksheet in writer.sheets.values():
            worksheet.freeze_panes = "A2"
            worksheet.auto_filter.ref = worksheet.dimensions  # header dropdown = sort high/low

            for column in worksheet.iter_cols():
                header = str(column[0].value or "").strip().lower()
                if "cost" in header or "amount" in header:
                    for cell in column[1:]:
                        if isinstance(cell.value, (int, float)):
                            cell.number_format = (
                                '$#,##0.0000;[Red]-$#,##0.0000'
                                if worksheet.title == "Final Summary"
                                else '$#,##0.00000000;[Red]-$#,##0.00000000')

                max_length = 0
                for cell in column:
                    try:
                        max_length = max(max_length, len(str(cell.value)))
                    except Exception:
                        pass
                worksheet.column_dimensions[column[0].column_letter].width = min(max_length + 3, 55)

    log(f"[SUCCESS] Report generated: {output}")


# ============================================================
# MAIN
# ============================================================

def main():
    global VERBOSE

    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    parser = argparse.ArgumentParser(description="AWS Cost and IAM Resource Audit")
    parser.add_argument("--profile", default=os.getenv("AWS_PROFILE", DEFAULT_PROFILE))
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--days", type=int, default=DEFAULT_DAYS)
    parser.add_argument("--output", default="AWS_Cost_IAM_Audit.xlsx")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print per-call progress")
    parser.add_argument("--debug", action="store_true",
                        help="log botocore HTTP requests/retries (very chatty)")
    parser.add_argument("--skip-cost", action="store_true",
                        help="skip Cost Explorer queries")
    parser.add_argument("--skip-cloudtrail", action="store_true",
                        help="skip CloudTrail scan (inventory + cost only)")
    parser.add_argument("--all-regions", action="store_true",
                        help="scan CloudTrail in ALL enabled regions (slow)")
    parser.add_argument("--region-budget", type=int, default=90,
                        help="max seconds of CloudTrail scanning per region (default 90)")
    parser.add_argument("--max-pages", type=int, default=40,
                        help="max CloudTrail pages (50 events each) per event type")
    parser.add_argument("--workers", type=int, default=4,
                        help="parallel CloudTrail regions (default 4)")
    args = parser.parse_args()

    VERBOSE = args.verbose or args.debug

    if args.debug:
        logging.basicConfig(level=logging.WARNING)
        boto3.set_stream_logger("botocore.endpoint", logging.DEBUG)
        boto3.set_stream_logger("botocore.retryhandler", logging.DEBUG)

    if args.days < 1 or args.days > 90:
        parser.error("--days must be between 1 and 90 for CloudTrail Event History.")

    log("======================================")
    log("        AWS COST + IAM AUDIT")
    log("======================================")

    try:
        session, identity = create_session(args.profile, args.region)
    except (ClientError, BotoCoreError) as exc:
        log(f"\nAWS authentication failed: {exc}")
        log("If you use an MFA session profile, your temporary credentials may "
            "have expired. Refresh them and retry.")
        return

    end_date = datetime.now(timezone.utc).date()
    start_date = end_date - timedelta(days=args.days)
    start, end = start_date.isoformat(), end_date.isoformat()
    log(f"\nAudit period: {start} -> {end} ({args.days} days)")

    service_cost = daily_cost = usage_cost = operation_cost = region_cost = []
    forecast, explanations = [], []
    resources, kiro, cloudtrail_events = [], [], []
    iam_attribution, iam_timeline, unidentified = [], [], []

    try:
        # 1. Inventory first, so resources show up immediately
        resources = get_current_resources(session, args.region)

        # 2. Cost Explorer
        if not args.skip_cost:
            log("\n[Cost] Querying Cost Explorer...")
            ce = get_client(session, "ce", "us-east-1")
            service_cost = get_service_cost(ce, start, end)
            daily_cost = get_daily_cost(ce, start, end)
            usage_cost = get_usage_breakdown(ce, start, end)
            operation_cost = get_operation_breakdown(ce, start, end)
            region_cost = get_region_cost(ce, start, end)
            forecast = get_cost_forecast(ce)
            explanations = explain_usage(usage_cost)

        # 3. Kiro diagnostic
        kiro = kiro_diagnostic(session, identity, args.region)

        # 4. CloudTrail
        if not args.skip_cloudtrail:
            if args.all_regions:
                regions = get_enabled_regions(session, args.region)
            else:
                regions = sorted({r["Region"] for r in resources if r.get("Region")}
                                 | {args.region})
            cloudtrail_events = get_cloudtrail_activity(
                session, regions, args.days,
                args.region_budget, args.workers, args.max_pages)
        else:
            log("\n[CloudTrail] Skipped (--skip-cloudtrail)")

    except KeyboardInterrupt:
        STOP.set()
        log("\n[Interrupted] Ctrl+C received - writing report with data collected so far...")

    # 5. Attribution + report (always runs, even after interrupt)
    iam_attribution, iam_timeline, unidentified = attribute_resources(
        resources, cloudtrail_events)

    missing_tags = get_missing_owner_tags(resources)

    final_summary = build_final_summary(
        region_cost, resources, iam_attribution, not args.skip_cloudtrail)

    sheets = [
        ("Final Summary", final_summary),
        ("Service Cost", service_cost),
        ("Daily Cost Trend", daily_cost),
        ("Usage Breakdown", usage_cost),
        ("Operation Breakdown", operation_cost),
        ("Region Breakdown", region_cost),
        ("Cost Forecast", forecast),
        ("Cost Explanation", explanations),
        ("Current Resources", resources),
        ("Missing Owner Tags", missing_tags),
        ("Kiro Diagnostic", kiro),
        ("IAM Resource Attribution", iam_attribution),
        ("IAM Activity Timeline", iam_timeline),
        ("Unidentified Resources", unidentified),
    ]
    generate_report(args.output, sheets)

    log("\n======================================")
    log("           AUDIT COMPLETED")
    log("======================================")
    log(f"Service Cost Rows:      {len(service_cost)}")
    log(f"Daily Cost Rows:        {len(daily_cost)}")
    log(f"Usage Breakdown Rows:   {len(usage_cost)}")
    log(f"Current Resources:      {len(resources)}")
    log(f"CloudTrail Events:      {len(cloudtrail_events)}")
    log(f"IAM Attribution Rows:   {len(iam_attribution)}")
    log(f"Unidentified Resources: {len(unidentified)}")
    log(f"Confirmed Creators:     "
        f"{sum(1 for r in iam_attribution if r.get('Attribution Status') == 'Creator Identified')}")
    log(f"\nExcel File: {args.output}")


if __name__ == "__main__":
    main()