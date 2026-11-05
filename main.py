#!/usr/bin/env python3
"""
AWS Cleanup Audit  (cost-first, tag-focused)

Goal: find billed resources that are not tagged, show who created them and what each
one costs, so untagged / unused resources can be cleaned up.

Flow
  1. Cost Explorer -> every Region + Service with cost > 0 (credits/refunds/tax excluded).
     These service totals are EXACT billing numbers.
  2. Only regions with cost are scanned for resources (tagging API + service scanners,
     incl. VPCs, EC2/EBS, RDS, EKS, Lambda, S3, Bedrock, SQS, SNS, KMS, Glue, ...).
  3. Per-resource cost (always a number):
        - "Exact (Cost Explorer)"   when Cost Explorer resource-level data is enabled
                                    (last 14 days only, opt-in in Cost Explorer settings)
        - "Estimated (usage split)" otherwise: each usage type's cost is split across the
                                    matching resources (EBS by GiB, others equally)
        - leftovers (data transfer, requests, deleted resources...) are shown on an
          "Unallocated" row, so every service's rows add up to its exact total.
  4. CloudTrail (90 days max) -> IAM user / role session that created each resource.
  5. Excel:
        Region-Service Summary   region -> service -> exact cost totals and status counts
        Resource Details         one row per resource; service total on first row only;
                                 Resource fields and Tags in separate columns
        Untagged Resources       the cleanup list
        Usage Breakdown          usage types per service with cost and % share

No time limits: every API call waits as long as it needs (long timeouts, many retries) and
CloudTrail lookups have no per-region budget unless you set --region-budget.

Usage
  python aws_cleanup_audit.py -v
  python aws_cleanup_audit.py --skip-cloudtrail          
  python aws_cleanup_audit.py --days 14                  
  python aws_cleanup_audit.py --ascending                
  python aws_cleanup_audit.py --min-cost 0.01
  python aws_cleanup_audit.py --required-tags Owner,Environment
"""

import argparse
import json
import os
import re
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

import boto3
import pandas as pd
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

DEFAULT_PROFILE = "mfa-session"
DEFAULT_REGION = "ap-south-1"
DEFAULT_DAYS = 10

VERBOSE = False
STOP = threading.Event()
_print_lock = threading.Lock()


# ============================================================
# HELPERS
# ============================================================

def log(msg="", verbose_only=False):
    if verbose_only and not VERBOSE:
        return
    with _print_lock:
        print(msg, flush=True)


def short(exc, n=160):
    return str(exc).replace("\n", " ")[:n]


def make_config():
    # Patient settings: slow responses are waited for, throttling is retried many times.
    return Config(connect_timeout=15, read_timeout=180,
                  retries={"max_attempts": 10, "mode": "adaptive"})


def get_client(session, service, region=None):
    return session.client(service, region_name=region, config=make_config())


def pages(client, op, **kw):
    """Paginate when the API supports it, otherwise a single call."""
    if client.can_paginate(op):
        for p in client.get_paginator(op).paginate(**kw):
            yield p
    else:
        yield getattr(client, op)(**kw)


def tags_of(tag_list):
    """Accepts [{'Key':..,'Value':..}], [{'key':..,'value':..}] or a dict."""
    if not tag_list:
        return {}
    if isinstance(tag_list, dict):
        return dict(tag_list)
    out = {}
    for t in tag_list:
        k = t.get("Key", t.get("key"))
        v = t.get("Value", t.get("value", ""))
        if k is not None:
            out[k] = v
    return out


def tag_string(tags):
    return "; ".join(f"{k}={v}" for k, v in sorted(tags.items()))


def resource_display(it):
    label = f"{it['Kind']} {it['ID']}"
    if it.get("Name") and it["Name"] != it["ID"]:
        label += f" ({it['Name']})"
    return label


def collapse_service_header_rows(rows):
    """Show Region, Service, and service total only on the first row of each block."""
    out = []
    for i, row in enumerate(rows):
        if i == 0:
            out.append(row)
            continue
        r = dict(row)
        r["Region"] = r["Service"] = r["Service Total (USD)"] = ""
        out.append(r)
    return out


SUMMARY_STATUS_PARTS = (
    ("Active", "Active"),
    ("Pending / Initializing", "Pending / Initializing"),
    ("Inactive / Stopped", "Inactive / Stopped"),
    ("Idle / Unattached", "Idle / Unattached"),
    ("Deleting / Failed", "Deleting / Failed"),
    ("Unknown", "Status Unknown"),
)


def format_status_summary(counts):
    """One column on Region-Service Summary: all status counts in a single cell."""
    return "; ".join(f"{label}: {counts.get(key, 0)}" for key, label in SUMMARY_STATUS_PARTS)


def strip_detail_columns(row):
    row.pop("Cost Basis", None)
    row.pop("Resource ARN", None)
    row.pop("Creator ARN", None)
    return row


# Display category (never lump VPC endpoints / EIPs into "VPC" counts).
KIND_TO_CATEGORY = {
    "vpc": "VPC",
    "subnet": "Subnet",
    "route-table": "Route Table",
    "security-group": "Security Group",
    "network-acl": "Network ACL",
    "internet-gateway": "Internet Gateway",
    "egress-only-internet-gateway": "Egress-only IGW",
    "vpc-peering-connection": "VPC Peering",
    "vpc-endpoint": "VPC Endpoint",
    "natgateway": "NAT Gateway",
    "elastic-ip": "Elastic IP",
    "network-interface": "Network Interface",
    "vpn-gateway": "VPN Gateway",
    "vpn-connection": "VPN Connection",
    "customer-gateway": "Customer Gateway",
    "flow-log": "VPC Flow Log",
    "instance": "EC2 Instance",
    "volume": "EBS Volume",
    "snapshot": "EBS Snapshot",
    "image": "AMI",
    "cluster": "EKS Cluster",
    "function": "Lambda Function",
    "bucket": "S3 Bucket",
    "db": "RDS Instance",
    "loadbalancer": "Load Balancer",
    "table": "DynamoDB Table",
    "repository": "ECR Repository",
    "secret": "Secrets Manager Secret",
    "key": "KMS Key",
    "log-group": "CloudWatch Log Group",
    "queue": "SQS Queue",
    "topic": "SNS Topic",
    "restapi": "API Gateway REST API",
    "httpapi": "API Gateway HTTP API",
    "hostedzone": "Route 53 Hosted Zone",
    "stateMachine": "Step Functions State Machine",
    "crawler": "Glue Crawler",
    "job": "Glue Job",
}

CATEGORY_SORT = {name: i for i, name in enumerate(KIND_TO_CATEGORY.values())}


def resource_category(it):
    kind = it.get("Kind") or ""
    if kind in KIND_TO_CATEGORY:
        return KIND_TO_CATEGORY[kind]
    svc = it.get("Svc") or ""
    if svc == "rds":
        return "RDS"
    if svc == "lambda":
        return "Lambda"
    if svc == "s3":
        return "S3"
    if svc == "dynamodb":
        return "DynamoDB"
    if svc == "elasticache":
        return "ElastiCache"
    if svc == "es" or svc == "aoss":
        return "OpenSearch"
    if svc == "sagemaker":
        return "SageMaker"
    if svc == "bedrock":
        return "Bedrock"
    if svc == "ecs":
        return "ECS"
    if svc == "eks":
        return "EKS"
    if svc == "redshift":
        return "Redshift"
    return kind.replace("-", " ").title() if kind else svc.upper()


def inventory_breakdown(its):
    """Counts by category, e.g. VPC: 3; Elastic IP: 6; VPC Endpoint: 1 (not 'VPC: 10')."""
    by_cat = defaultdict(int)
    for it in its:
        by_cat[resource_category(it)] += 1
    parts = sorted(by_cat.items(), key=lambda x: (CATEGORY_SORT.get(x[0], 999), x[0]))
    return "; ".join(f"{cat}: {n}" for cat, n in parts)


def category_sort_key(it):
    cat = resource_category(it)
    return (CATEGORY_SORT.get(cat, 999), cat, it.get("Kind", ""), it.get("ID", ""))


def fmt_dt(v):
    if v is None or v == "":
        return ""
    if isinstance(v, datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return str(v)


def parse_arn(arn):
    """-> (service, region, resource_type, resource_id)"""
    p = arn.split(":", 5)
    if len(p) < 6:
        return "", "", "", arn
    service, region, res = p[2], p[3], p[5]
    m = re.match(r"([^/:]+)[/:](.+)", res)
    rtype, rid = (m.group(1), m.group(2)) if m else ("", res)
    return service, region, rtype, rid


# ============================================================
# STATUS NORMALISATION
# ============================================================

ACTIVE = {"running", "available", "in-use", "in_use", "active", "inservice", "in_service",
          "ready", "completed", "enabled", "associated", "healthy", "attached", "normal",
          "succeeded", "valid", "issued", "online", "deployed", "prepared"}
PENDING = {"pending", "creating", "starting", "provisioning", "initializing", "updating",
           "modifying", "backing-up", "upgrading", "rebooting", "in_progress", "inprogress",
           "processing", "importing", "scaling", "renaming", "configuring-enhanced-monitoring",
           "storage-optimization", "resetting-master-credentials", "pending-update"}
INACTIVE = {"stopped", "stopping", "inactive", "disabled", "stopped-by-aws", "offline"}
BAD = {"deleting", "deleted", "failed", "error", "terminated", "shutting-down",
       "create_failed", "delete_failed", "active_impaired", "unhealthy"}


def normalize_status(raw):
    s = (raw or "").lower().strip()
    if not s or s == "unknown":
        return "Unknown"
    if "unattached" in s or "unassociated" in s:
        return "Idle / Unattached"
    if s in ACTIVE:
        return "Active"
    if s in PENDING:
        return "Pending / Initializing"
    if s in INACTIVE:
        return "Inactive / Stopped"
    if s in BAD:
        return "Deleting / Failed"
    return "Unknown"


# ============================================================
# BILLING NAME <-> RESOURCE MAPPING
# ============================================================
# Lower-case substrings of the Cost Explorer service name, by ARN service.

SERVICE_COST_KEYS = {
    "lambda": ["lambda"],
    "s3": ["simple storage service"],
    "rds": ["relational database"],
    "dynamodb": ["dynamodb"],
    "eks": ["kubernetes"],
    "ecs": ["elastic container service", "container service"],
    "ecr": ["container registry"],
    "elasticloadbalancing": ["elastic load balancing"],
    "bedrock": ["bedrock"],
    "sagemaker": ["sagemaker"],
    "es": ["opensearch", "elasticsearch"],
    "aoss": ["opensearch"],
    "elasticache": ["elasticache"],
    "redshift": ["redshift"],
    "logs": ["cloudwatch"],
    "cloudwatch": ["cloudwatch"],
    "secretsmanager": ["secrets manager"],
    "kms": ["key management"],
    "sqs": ["queue service"],
    "sns": ["notification service"],
    "cloudfront": ["cloudfront"],
    "states": ["step functions"],
    "glue": ["glue"],
    "athena": ["athena"],
    "kinesis": ["kinesis"],
    "apigateway": ["api gateway"],
    "elasticfilesystem": ["elastic file system"],
    "ssm": ["systems manager"],
    "route53": ["route 53"],
    "transfer": ["transfer family"],
    "mq": ["amazon mq"],
    "kafka": ["managed streaming"],
    "firehose": ["firehose"],
    "events": ["eventbridge", "cloudwatch events"],
    "wafv2": ["waf"],
    "backup": ["backup"],
}

BILLABLE_EC2 = {"instance", "volume", "snapshot", "natgateway", "elastic-ip",
                "vpc-endpoint", "image", "vpc"}


def is_vpc_billing_service(service_name):
    return "virtual private cloud" in (service_name or "").lower()


def cost_keys_for(svc, kind):
    if svc == "ec2":
        if kind == "instance":
            return ["elastic compute cloud - compute", "ec2 - other"]
        if kind == "vpc":
            return ["virtual private cloud"]
        # Billed under VPC line in Cost Explorer — separate categories in the report.
        if kind in ("elastic-ip", "vpc-endpoint", "natgateway", "vpn-gateway", "vpn-connection",
                    "customer-gateway"):
            return ["virtual private cloud", "ec2 - other"]
        return ["ec2 - other"]
    return SERVICE_COST_KEYS.get(svc) or [svc]


# ============================================================
# COST EXPLORER  (service totals = exact)
# ============================================================

COST_FILTER = {"Not": {"Dimensions": {"Key": "RECORD_TYPE",
                                      "Values": ["Credit", "Refund", "Tax"]}}}


def ce_query(ce, start, end, dims, filter_expr=None):
    if len(dims) > 2:
        raise ValueError(f"Cost Explorer allows at most 2 GroupBy dimensions, got {len(dims)}")
    params = {
        "TimePeriod": {"Start": start, "End": end},
        "Granularity": "MONTHLY",
        "Metrics": ["UnblendedCost"],
        "GroupBy": [{"Type": "DIMENSION", "Key": d} for d in dims],
        "Filter": filter_expr or COST_FILTER,
    }
    out = defaultdict(float)
    while True:
        resp = ce.get_cost_and_usage(**params)
        for period in resp.get("ResultsByTime", []):
            for g in period.get("Groups", []):
                out[tuple(g["Keys"])] += float(g["Metrics"]["UnblendedCost"]["Amount"])
        token = resp.get("NextPageToken")
        if not token:
            break
        params["NextPageToken"] = token
    return out


def service_filter(region, svc):
    return {"And": [COST_FILTER,
                    {"Dimensions": {"Key": "REGION", "Values": [region]}},
                    {"Dimensions": {"Key": "SERVICE", "Values": [svc]}}]}


def get_costs(ce, start, end, min_cost):
    log("\n[Billing] Cost by region + service (credits/refunds/tax excluded)...")
    raw = ce_query(ce, start, end, ["REGION", "SERVICE"])
    costs = {k: round(v, 4) for k, v in raw.items() if round(v, 4) > min_cost}
    log(f"   {len(costs)} region/service pairs with cost > ${min_cost}")

    usage = defaultdict(list)
    log("[Billing] Usage types per region + service...")
    for n, (region, svc) in enumerate(sorted(costs.keys()), 1):
        log(f"   usage {n}/{len(costs)}: {region} / {svc[:45]}", verbose_only=True)
        try:
            raw_u = ce_query(ce, start, end, ["USAGE_TYPE"],
                             filter_expr=service_filter(region, svc))
            for (ut,), v in raw_u.items():
                if round(v, 4) > 0:
                    usage[(region, svc)].append((ut, round(v, 4)))
            usage[(region, svc)].sort(key=lambda x: x[1], reverse=True)
        except (ClientError, BotoCoreError) as exc:
            log(f"[WARNING] Usage types for {region}/{svc[:30]}: {short(exc)}")
    log(f"   usage breakdown for {len(usage)} region/service pairs")
    return costs, usage


def fetch_resource_costs(ce, start, end, service_keys):
    """
    Exact per-resource cost from GetCostAndUsageWithResources (needs resource-level data
    enabled in Cost Explorer; AWS only keeps the last 14 days).
    Returns {(region, service, resource_id): usd}.
    """
    out = defaultdict(float)
    warned = False
    log("\n[Billing] Fetching exact per-resource costs (Cost Explorer resource-level data)...")
    keys = sorted(service_keys)
    for n, (region, svc) in enumerate(keys, 1):
        params = {
            "TimePeriod": {"Start": start, "End": end},
            "Granularity": "DAILY",
            "Metrics": ["UnblendedCost"],
            "GroupBy": [{"Type": "DIMENSION", "Key": "RESOURCE_ID"}],
            "Filter": service_filter(region, svc),
        }
        log(f"   resource cost {n}/{len(keys)}: {region} / {svc[:45]}", verbose_only=True)
        token = None
        while True:
            if token:
                params["NextPageToken"] = token
            else:
                params.pop("NextPageToken", None)
            try:
                resp = ce.get_cost_and_usage_with_resources(**params)
            except (ClientError, BotoCoreError) as exc:
                if not warned:
                    log("[Billing] Cost Explorer resource-level data is not available "
                        f"({short(exc, 220)}).\n"
                        "          Per-resource costs will be ESTIMATED from usage types. To get exact\n"
                        "          numbers, enable resource-level data in Billing and Cost Management ->\n"
                        "          Cost Explorer settings (payer account), wait ~24h, and re-run.")
                    warned = True
                break
            for period in resp.get("ResultsByTime", []):
                for g in period.get("Groups", []):
                    keys_ = g.get("Keys") or []
                    if not keys_:
                        continue
                    amt = float(g["Metrics"]["UnblendedCost"]["Amount"])
                    if amt:
                        out[(region, svc, keys_[0])] += amt
            token = resp.get("NextPageToken")
            if not token:
                break
    out = {k: round(v, 4) for k, v in out.items() if round(v, 4) > 0}
    log(f"   {len(out)} resource cost entries from Cost Explorer" if out else
        "   no resource-level entries returned; using usage-type estimates")
    return out


def build_exact_index(raw):
    idx = defaultdict(dict)
    for (region, svc, rid), c in raw.items():
        idx[(region, svc)][rid] = idx[(region, svc)].get(rid, 0.0) + c
    return idx


def ce_resource_id_aliases(raw):
    raw = (raw or "").strip()
    if not raw:
        return set()
    out = {raw}
    if raw.startswith("arn:"):
        tail = raw.split(":", 5)[-1]
        out |= {tail, tail.split("/")[-1], tail.rsplit(":", 1)[-1]}
    else:
        if "/" in raw:
            out.add(raw.split("/")[-1])
        if ":" in raw:
            out.add(raw.rsplit(":", 1)[-1])
    return {x for x in out if x}


def match_exact(its, pool):
    """Match inventory items to Cost Explorer resource IDs. -> (item_key->cost, leftovers)."""
    alias_to_rid = {}
    for rid in pool:
        for a in ce_resource_id_aliases(rid):
            alias_to_rid.setdefault(a, rid)
    used, got = set(), {}
    for it in its:
        keys = ({it["ID"], it["ARN"]} | ce_resource_id_aliases(it["ID"])
                | ce_resource_id_aliases(it["ARN"]))
        for k in keys:
            rid = alias_to_rid.get(k)
            if rid and rid not in used:
                used.add(rid)
                got[it["Key"]] = pool[rid]
                break
    leftovers = {rid: c for rid, c in pool.items() if rid not in used}
    return got, leftovers


# ---- usage-type based estimate (used when exact data is unavailable) ----

# First match wins, so specific patterns come first.
USAGE_HINTS = [
    (re.compile(r"NatGateway", re.I), {"natgateway"}),
    (re.compile(r"PublicIPv4|InUseAddress|IdleAddress|ElasticIP", re.I), {"elastic-ip"}),
    (re.compile(r"VpcEndpoint|PrivateLink", re.I), {"vpc-endpoint"}),
    (re.compile(r"Snapshot", re.I), {"snapshot"}),
    (re.compile(r"EBS:|VolumeUsage|VolumeP-IOPS|VolumeIOPS|VolumeThroughput", re.I), {"volume"}),
    (re.compile(r"BoxUsage|SpotUsage|DedicatedUsage", re.I), {"instance"}),
    (re.compile(r"EKS|Kubernetes|ClusterUsage|Fargate", re.I), {"cluster", "instance", "volume"}),
    (re.compile(r"LoadBalancerUsage|LCUUsage|LoadBalancer", re.I), {"loadbalancer"}),
    (re.compile(r"NodeUsage|CacheUsage", re.I), {"cluster"}),
    (re.compile(r"InstanceUsage|Multi-AZUsage|Aurora", re.I), {"db"}),
    (re.compile(r"Storage|Backup|IOUsage|PIOPS", re.I), {"db", "cluster", "bucket", "repository"}),
    (re.compile(r"KMS-Keys", re.I), {"key"}),
    (re.compile(r"Secrets", re.I), {"secret"}),
]

FREE_KINDS = {"vpc"}   # resource types that carry no charge themselves


def kinds_for_usage_type(ut):
    for pat, kinds in USAGE_HINTS:
        if pat.search(ut or ""):
            return kinds
    return set()


def estimate_costs(its, usage_rows, service_name=""):
    present = {it["Kind"] for it in its}
    svc_l = (service_name or "").lower()
    est = defaultdict(float)
    for ut, ut_cost in usage_rows:
        kinds = kinds_for_usage_type(ut) & present
        if kinds:
            pool = [it for it in its if it["Kind"] in kinds]
        elif "kubernetes" in svc_l:
            pool = list(its)
        elif len(present) == 1:
            pool = list(its)
        else:
            continue
        weights = [max(float(it.get("Weight", 1) or 1), 0.0001) for it in pool]
        total_w = sum(weights)
        for it, w in zip(pool, weights):
            est[it["Key"]] += ut_cost * w / total_w
    return {k: round(v, 4) for k, v in est.items()}


def allocate_costs(its, total, usage_rows, exact_pool, service_name=""):
    """
    -> (item_costs {key: (usd, basis)}, extras [(ce_resource_id, usd)], unallocated_usd)
    Estimated paths reconcile so resource rows sum to the exact service total from AWS.
    """
    item_costs, extras = {}, []
    paid = [it for it in its if it["Kind"] not in FREE_KINDS]
    for it in its:
        if it["Kind"] in FREE_KINDS:
            item_costs[it["Key"]] = (0.0, "")

    if exact_pool:
        got, leftovers = match_exact(paid, exact_pool)
        for it in paid:
            item_costs[it["Key"]] = (round(got.get(it["Key"], 0.0), 4), "")
        for rid, c in leftovers.items():
            if c >= 0.0001 and rid.lower() != "noresourceid":
                extras.append((rid, round(c, 4)))
    else:
        est = estimate_costs(paid, usage_rows, service_name)
        for it in paid:
            item_costs[it["Key"]] = (est.get(it["Key"], 0.0), "")

    assigned = sum(c for c, _ in item_costs.values()) + sum(c for _, c in extras)
    unalloc = round(total - assigned, 4)

    if not exact_pool and paid and unalloc >= 0.0001:
        pool = [it for it in paid if item_costs[it["Key"]][0] > 0] or paid
        weights = [max(float(it.get("Weight", 1) or 1), 0.0001) for it in pool]
        tw = sum(weights)
        for it, w in zip(pool, weights):
            c, _ = item_costs[it["Key"]]
            item_costs[it["Key"]] = (round(c + unalloc * w / tw, 4), "")
        unalloc = 0.0
    elif not exact_pool and paid and unalloc <= -0.0001:
        pool = [it for it in paid if item_costs[it["Key"]][0] > 0]
        if pool:
            excess = -unalloc
            tw = sum(item_costs[it["Key"]][0] for it in pool)
            if tw > 0:
                for it in pool:
                    c, _ = item_costs[it["Key"]]
                    item_costs[it["Key"]] = (round(max(c - excess * c / tw, 0.0), 4), "")
                assigned = sum(c for c, _ in item_costs.values()) + sum(c for _, c in extras)
                unalloc = round(total - assigned, 4)

    return item_costs, extras, max(unalloc, 0.0)


# ============================================================
# RESOURCE SCANNING
# ============================================================

class Scan:
    def __init__(self, session, region, acct, partition):
        self.session, self.region = session, region
        self.acct, self.partition = acct, partition
        self.items = {}

    def client(self, svc):
        return get_client(self.session, svc, self.region)

    def arn(self, svc, res, with_account=True):
        acct = self.acct if with_account else ""
        return f"arn:{self.partition}:{svc}:{self.region}:{acct}:{res}"

    def add(self, arn, name, state, tags, created=None, kind=None, rid=None, weight=1.0):
        svc, _, rtype, parsed_id = parse_arn(arn)
        kind = kind or rtype or svc
        rid = rid or parsed_id
        self.items[arn] = {
            "Key": arn, "ARN": arn, "Region": self.region, "Svc": svc, "Kind": kind,
            "ID": rid, "Name": name or "", "State": state or "unknown",
            "Tags": tags or {}, "Created": created, "CostService": None, "Weight": weight,
            "Attribution": "Not checked", "CreatedBy": "", "PrincipalType": "",
            "ViaRole": "", "CreatorARN": "", "CreatedAt": "",
        }


def sc_ec2(s):
    ec2 = s.client("ec2")
    for p in pages(ec2, "describe_instances"):
        for r in p.get("Reservations", []):
            for i in r.get("Instances", []):
                st = i["State"]["Name"]
                if st == "terminated":
                    continue
                t = tags_of(i.get("Tags"))
                s.add(s.arn("ec2", f"instance/{i['InstanceId']}"), t.get("Name"), st, t,
                      i.get("LaunchTime"))
    for p in pages(ec2, "describe_volumes"):
        for v in p.get("Volumes", []):
            t = tags_of(v.get("Tags"))
            st = "available (unattached)" if v["State"] == "available" else v["State"]
            s.add(s.arn("ec2", f"volume/{v['VolumeId']}"), t.get("Name"), st, t,
                  v.get("CreateTime"), weight=float(v.get("Size") or 1))
    for p in pages(ec2, "describe_snapshots", OwnerIds=["self"]):
        for sn in p.get("Snapshots", []):
            t = tags_of(sn.get("Tags"))
            s.add(s.arn("ec2", f"snapshot/{sn['SnapshotId']}", with_account=False),
                  t.get("Name"), sn.get("State"), t, sn.get("StartTime"),
                  weight=float(sn.get("VolumeSize") or 1))
    for p in pages(ec2, "describe_nat_gateways"):
        for n in p.get("NatGateways", []):
            if n.get("State") == "deleted":
                continue
            t = tags_of(n.get("Tags"))
            s.add(s.arn("ec2", f"natgateway/{n['NatGatewayId']}"), t.get("Name"),
                  n.get("State"), t, n.get("CreateTime"))
    for a in ec2.describe_addresses().get("Addresses", []):
        if not a.get("AllocationId"):
            continue
        t = tags_of(a.get("Tags"))
        st = "associated" if a.get("AssociationId") else "unassociated"
        s.add(s.arn("ec2", f"elastic-ip/{a['AllocationId']}"), t.get("Name"), st, t)
    for p in pages(ec2, "describe_vpc_endpoints"):
        for e in p.get("VpcEndpoints", []):
            if str(e.get("State", "")).lower() == "deleted":
                continue
            t = tags_of(e.get("Tags"))
            s.add(s.arn("ec2", f"vpc-endpoint/{e['VpcEndpointId']}"), t.get("Name"),
                  e.get("State"), t, e.get("CreationTimestamp"))
    for p in pages(ec2, "describe_images", Owners=["self"]):
        for im in p.get("Images", []):
            t = tags_of(im.get("Tags"))
            s.add(s.arn("ec2", f"image/{im['ImageId']}", with_account=False),
                  im.get("Name"), im.get("State"), t, im.get("CreationDate"))
    for p in pages(ec2, "describe_vpcs"):
        for v in p.get("Vpcs", []):
            t = tags_of(v.get("Tags"))
            label = t.get("Name") or v.get("CidrBlock", "")
            if v.get("IsDefault"):
                label += " (default VPC)"
            s.add(s.arn("ec2", f"vpc/{v['VpcId']}"), label, v.get("State"), t)


def sc_rds(s):
    rds = s.client("rds")
    for p in pages(rds, "describe_db_instances"):
        for d in p.get("DBInstances", []):
            s.add(d["DBInstanceArn"], d["DBInstanceIdentifier"], d.get("DBInstanceStatus"),
                  tags_of(d.get("TagList")), d.get("InstanceCreateTime"))
    for p in pages(rds, "describe_db_clusters"):
        for d in p.get("DBClusters", []):
            s.add(d["DBClusterArn"], d["DBClusterIdentifier"], d.get("Status"),
                  tags_of(d.get("TagList")), d.get("ClusterCreateTime"))


def sc_lambda(s):
    lam = s.client("lambda")
    for p in pages(lam, "list_functions"):
        for f in p.get("Functions", []):
            s.add(f["FunctionArn"], f["FunctionName"], f.get("State") or "Active", {},
                  f.get("LastModified"))


def sc_eks(s):
    eks = s.client("eks")
    for p in pages(eks, "list_clusters"):
        for name in p.get("clusters", []):
            c = eks.describe_cluster(name=name)["cluster"]
            s.add(c["arn"], name, c.get("status"), tags_of(c.get("tags")), c.get("createdAt"))


def sc_ecs(s):
    ecs = s.client("ecs")
    arns = []
    for p in pages(ecs, "list_clusters"):
        arns.extend(p.get("clusterArns", []))
    for i in range(0, len(arns), 100):
        resp = ecs.describe_clusters(clusters=arns[i:i + 100], include=["TAGS"])
        for c in resp.get("clusters", []):
            s.add(c["clusterArn"], c.get("clusterName"), c.get("status"),
                  tags_of(c.get("tags")))


def sc_elbv2(s):
    elb = s.client("elbv2")
    for p in pages(elb, "describe_load_balancers"):
        for lb in p.get("LoadBalancers", []):
            s.add(lb["LoadBalancerArn"], lb.get("LoadBalancerName"),
                  lb.get("State", {}).get("Code"), {}, lb.get("CreatedTime"))


def sc_classic_elb(s):
    elb = s.client("elb")
    for p in pages(elb, "describe_load_balancers"):
        for lb in p.get("LoadBalancerDescriptions", []):
            n = lb["LoadBalancerName"]
            s.add(s.arn("elasticloadbalancing", f"loadbalancer/{n}"), n, "active", {},
                  lb.get("CreatedTime"))


def sc_dynamodb(s):
    ddb = s.client("dynamodb")
    for p in pages(ddb, "list_tables"):
        for name in p.get("TableNames", []):
            t = ddb.describe_table(TableName=name)["Table"]
            s.add(t["TableArn"], name, t.get("TableStatus"), {}, t.get("CreationDateTime"))


def sc_elasticache(s):
    ec = s.client("elasticache")
    for p in pages(ec, "describe_cache_clusters"):
        for c in p.get("CacheClusters", []):
            if c.get("ARN"):
                s.add(c["ARN"], c["CacheClusterId"], c.get("CacheClusterStatus"), {},
                      c.get("CacheClusterCreateTime"))


def sc_opensearch(s):
    os_ = s.client("opensearch")
    names = [d["DomainName"] for d in os_.list_domain_names().get("DomainNames", [])]
    for i in range(0, len(names), 5):
        for d in os_.describe_domains(DomainNames=names[i:i + 5]).get("DomainStatusList", []):
            if d.get("Deleted"):
                continue
            st = "processing" if d.get("Processing") else "active"
            s.add(d["ARN"], d["DomainName"], st, {})


def sc_sagemaker(s):
    sm = s.client("sagemaker")
    for p in pages(sm, "list_endpoints"):
        for e in p.get("Endpoints", []):
            s.add(e["EndpointArn"], e["EndpointName"], e.get("EndpointStatus"), {},
                  e.get("CreationTime"))
    for p in pages(sm, "list_notebook_instances"):
        for n in p.get("NotebookInstances", []):
            s.add(n["NotebookInstanceArn"], n["NotebookInstanceName"],
                  n.get("NotebookInstanceStatus"), {}, n.get("CreationTime"))


def sc_sagemaker_extra(s):
    sm = s.client("sagemaker")
    try:
        for p in pages(sm, "list_domains"):
            for d in p.get("Domains", []):
                s.add(d["DomainArn"], d.get("DomainName"), d.get("Status"), {},
                      d.get("CreationTime"))
    except Exception as exc:
        log(f"[WARN] {s.region} SageMaker domains: {short(exc)}", True)
    try:
        for p in pages(sm, "list_apps"):
            for a in p.get("Apps", []):
                if a.get("Status") in ("Deleted", "Deleting"):
                    continue
                owner = a.get("UserProfileName") or a.get("SpaceName") or "-"
                s.add(s.arn("sagemaker", f"app/{a['DomainId']}/{owner}/{a['AppType']}/"
                                         f"{a['AppName']}"),
                      f"{a['AppType']}/{a['AppName']}", a.get("Status"), {},
                      a.get("CreationTime"), kind="app")
    except Exception as exc:
        log(f"[WARN] {s.region} SageMaker apps: {short(exc)}", True)
    for op, key, arn_key, name_key in (
            ("list_training_jobs", "TrainingJobSummaries", "TrainingJobArn", "TrainingJobName"),
            ("list_processing_jobs", "ProcessingJobSummaries", "ProcessingJobArn",
             "ProcessingJobName")):
        try:
            for p in pages(sm, op, StatusEquals="InProgress"):
                for j in p.get(key, []):
                    s.add(j[arn_key], j[name_key], "running", {}, j.get("CreationTime"))
        except Exception as exc:
            log(f"[WARN] {s.region} SageMaker {op}: {short(exc)}", True)


def sc_bedrock(s):
    br = s.client("bedrock")
    try:
        for p in pages(br, "list_provisioned_model_throughputs"):
            for m in p.get("provisionedModelSummaries", []):
                s.add(m["provisionedModelArn"], m.get("provisionedModelName"),
                      m.get("status"), {}, m.get("creationTime"))
    except Exception as exc:
        log(f"[WARN] {s.region} Bedrock provisioned throughput: {short(exc)}", True)
    for op, key, label in (("list_custom_models", "modelSummaries", "custom model"),
                           ("list_imported_models", "modelSummaries", "imported model")):
        try:
            for p in pages(br, op):
                for m in p.get(key, []):
                    s.add(m["modelArn"], m.get("modelName"), "active", {},
                          m.get("creationTime"))
        except Exception as exc:
            log(f"[WARN] {s.region} Bedrock {label}: {short(exc)}", True)
    try:
        for p in pages(br, "list_guardrails"):
            for g in p.get("guardrails", []):
                s.add(g["arn"], g.get("name"), g.get("status"), {}, g.get("createdAt"))
    except Exception as exc:
        log(f"[WARN] {s.region} Bedrock guardrails: {short(exc)}", True)
    ba = s.client("bedrock-agent")
    try:
        for p in pages(ba, "list_agents"):
            for a in p.get("agentSummaries", []):
                s.add(s.arn("bedrock", f"agent/{a['agentId']}"), a.get("agentName"),
                      a.get("agentStatus"), {}, a.get("updatedAt"))
    except Exception as exc:
        log(f"[WARN] {s.region} Bedrock agents: {short(exc)}", True)
    try:
        for p in pages(ba, "list_knowledge_bases"):
            for k in p.get("knowledgeBaseSummaries", []):
                s.add(s.arn("bedrock", f"knowledge-base/{k['knowledgeBaseId']}"),
                      k.get("name"), k.get("status"), {}, k.get("updatedAt"))
    except Exception as exc:
        log(f"[WARN] {s.region} Bedrock knowledge bases: {short(exc)}", True)


def sc_bedrock_extra(s):
    br = s.client("bedrock")
    try:
        for p in pages(br, "list_inference_profiles", typeEquals="APPLICATION"):
            for ip in p.get("inferenceProfileSummaries", []):
                s.add(ip["inferenceProfileArn"], ip.get("inferenceProfileName"),
                      ip.get("status"), {}, ip.get("createdAt"))
    except Exception as exc:
        log(f"[WARN] {s.region} Bedrock inference profiles: {short(exc)}", True)
    ba = s.client("bedrock-agent")
    for op, key, label in (("list_flows", "flowSummaries", "flows"),
                           ("list_prompts", "promptSummaries", "prompts")):
        try:
            for p in pages(ba, op):
                for x in p.get(key, []):
                    s.add(x["arn"], x.get("name"), x.get("status") or "active", {},
                          x.get("createdAt"))
        except Exception as exc:
            log(f"[WARN] {s.region} Bedrock {label}: {short(exc)}", True)


def sc_logs(s):
    logs = s.client("logs")
    for p in pages(logs, "describe_log_groups"):
        for g in p.get("logGroups", []):
            arn = g["arn"][:-2] if g["arn"].endswith(":*") else g["arn"]
            created = datetime.fromtimestamp(g["creationTime"] / 1000, tz=timezone.utc) \
                if g.get("creationTime") else None
            s.add(arn, g["logGroupName"], "active", {}, created)


def sc_cloudwatch(s):
    cw = s.client("cloudwatch")
    for p in pages(cw, "describe_alarms", AlarmTypes=["MetricAlarm", "CompositeAlarm"]):
        for a in (p.get("MetricAlarms", []) + p.get("CompositeAlarms", [])):
            s.add(a["AlarmArn"], a["AlarmName"], "active", {},
                  a.get("AlarmConfigurationUpdatedTimestamp"))
    for p in pages(cw, "list_dashboards"):
        for d in p.get("DashboardEntries", []):
            s.add(d["DashboardArn"], d["DashboardName"], "active", {}, d.get("LastModified"))


def sc_secrets(s):
    sm = s.client("secretsmanager")
    for p in pages(sm, "list_secrets"):
        for x in p.get("SecretList", []):
            if x.get("DeletedDate"):
                continue
            s.add(x["ARN"], x["Name"], "active", tags_of(x.get("Tags")), x.get("CreatedDate"))


def sc_redshift(s):
    rs = s.client("redshift")
    for p in pages(rs, "describe_clusters"):
        for c in p.get("Clusters", []):
            s.add(s.arn("redshift", f"cluster:{c['ClusterIdentifier']}"),
                  c["ClusterIdentifier"], c.get("ClusterStatus"), tags_of(c.get("Tags")),
                  c.get("ClusterCreateTime"))


def sc_ecr(s):
    ecr = s.client("ecr")
    for p in pages(ecr, "describe_repositories"):
        for r in p.get("repositories", []):
            s.add(r["repositoryArn"], r["repositoryName"], "active", {}, r.get("createdAt"))


def sc_sqs(s):
    sqs = s.client("sqs")
    for p in pages(sqs, "list_queues"):
        for url in p.get("QueueUrls") or []:
            name = url.rsplit("/", 1)[-1]
            s.add(s.arn("sqs", name), name, "active", {})


def sc_sns(s):
    sns = s.client("sns")
    for p in pages(sns, "list_topics"):
        for t in p.get("Topics", []):
            s.add(t["TopicArn"], t["TopicArn"].rsplit(":", 1)[-1], "active", {})


def sc_kms(s):
    kms = s.client("kms")
    aliases = {}
    for p in pages(kms, "list_aliases"):
        for a in p.get("Aliases", []):
            if a.get("TargetKeyId") and not a["AliasName"].startswith("alias/aws/"):
                aliases[a["TargetKeyId"]] = a["AliasName"]
    for p in pages(kms, "list_keys"):
        for k in p.get("Keys", []):
            try:
                m = kms.describe_key(KeyId=k["KeyId"])["KeyMetadata"]
            except (ClientError, BotoCoreError):
                continue
            if m.get("KeyManager") != "CUSTOMER" or m.get("KeyState") == "PendingDeletion":
                continue
            s.add(m["Arn"], aliases.get(m["KeyId"], m["KeyId"]), m.get("KeyState", "Enabled"),
                  {}, m.get("CreationDate"))


def sc_stepfunctions(s):
    sf = s.client("stepfunctions")
    for p in pages(sf, "list_state_machines"):
        for m in p.get("stateMachines", []):
            s.add(m["stateMachineArn"], m["name"], "active", {}, m.get("creationDate"))


def sc_glue(s):
    glue = s.client("glue")
    for p in pages(glue, "get_crawlers"):
        for c in p.get("Crawlers", []):
            s.add(s.arn("glue", f"crawler/{c['Name']}"), c["Name"], c.get("State", "READY"),
                  {}, c.get("CreationTime"))
    for p in pages(glue, "list_jobs"):
        for name in p.get("JobNames", []):
            s.add(s.arn("glue", f"job/{name}"), name, "active", {})
    try:
        for p in pages(glue, "get_dev_endpoints"):
            for e in p.get("DevEndpoints", []):
                s.add(s.arn("glue", f"devEndpoint/{e['EndpointName']}"), e["EndpointName"],
                      e.get("Status"), {}, e.get("CreatedTimestamp"))
    except Exception as exc:
        log(f"[WARN] {s.region} Glue dev endpoints: {short(exc)}", True)


def sc_apigateway(s):
    ag = s.client("apigateway")
    for p in pages(ag, "get_rest_apis"):
        for a in p.get("items", []):
            s.add(f"arn:{s.partition}:apigateway:{s.region}::/restapis/{a['id']}",
                  a.get("name"), "active", tags_of(a.get("tags")), a.get("createdDate"),
                  kind="restapi", rid=a["id"])
    try:
        v2 = s.client("apigatewayv2")
        token = None
        while True:
            r = v2.get_apis(**({"NextToken": token} if token else {}))
            for a in r.get("Items", []):
                s.add(f"arn:{s.partition}:apigateway:{s.region}::/apis/{a['ApiId']}",
                      a.get("Name"), "active", tags_of(a.get("Tags")), a.get("CreatedDate"),
                      kind="httpapi", rid=a["ApiId"])
            token = r.get("NextToken")
            if not token:
                break
    except Exception as exc:
        log(f"[WARN] {s.region} API Gateway v2: {short(exc)}", True)


def sc_efs(s):
    efs = s.client("efs")
    for p in pages(efs, "describe_file_systems"):
        for f in p.get("FileSystems", []):
            s.add(f["FileSystemArn"], f.get("Name") or f["FileSystemId"],
                  f.get("LifeCycleState"), tags_of(f.get("Tags")), f.get("CreationTime"))


def sc_kinesis(s):
    k = s.client("kinesis")
    for p in pages(k, "list_streams"):
        for name in p.get("StreamNames", []):
            d = k.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
            s.add(d["StreamARN"], name, d.get("StreamStatus"), {},
                  d.get("StreamCreationTimestamp"))


def sc_msk(s):
    k = s.client("kafka")
    for p in pages(k, "list_clusters_v2"):
        for c in p.get("ClusterInfoList", []):
            s.add(c["ClusterArn"], c["ClusterName"], c.get("State"), tags_of(c.get("Tags")),
                  c.get("CreationTime"))


def sc_mq(s):
    mq = s.client("mq")
    for p in pages(mq, "list_brokers"):
        for b in p.get("BrokerSummaries", []):
            s.add(b["BrokerArn"], b.get("BrokerName"), b.get("BrokerState"), {},
                  b.get("Created"))


def sc_transfer(s):
    tr = s.client("transfer")
    for p in pages(tr, "list_servers"):
        for sv in p.get("Servers", []):
            s.add(sv["Arn"], sv["ServerId"], sv.get("State"), {})


def sc_cloudfront(s):
    cf = s.client("cloudfront")
    for p in pages(cf, "list_distributions"):
        for d in (p.get("DistributionList") or {}).get("Items") or []:
            s.add(d["ARN"], d.get("DomainName") or d["Id"], d.get("Status"), {},
                  d.get("LastModifiedTime"), rid=d["Id"])


def sc_route53(s):
    r53 = s.client("route53")
    for p in pages(r53, "list_hosted_zones"):
        for z in p.get("HostedZones", []):
            zid = z["Id"].split("/")[-1]
            s.add(f"arn:{s.partition}:route53:::hostedzone/{zid}", z["Name"].rstrip("."),
                  "active", {}, kind="hostedzone", rid=zid)


SCANNERS = [
    ("EC2/EBS/NAT/EIP/AMI/VPC", sc_ec2), ("RDS", sc_rds), ("Lambda", sc_lambda),
    ("EKS", sc_eks), ("ECS", sc_ecs), ("ELBv2", sc_elbv2), ("Classic ELB", sc_classic_elb),
    ("DynamoDB", sc_dynamodb), ("ElastiCache", sc_elasticache),
    ("OpenSearch", sc_opensearch), ("SageMaker", sc_sagemaker),
    ("SageMaker Studio/jobs", sc_sagemaker_extra), ("Bedrock", sc_bedrock),
    ("Bedrock extras", sc_bedrock_extra), ("CloudWatch Logs", sc_logs),
    ("CloudWatch alarms/dashboards", sc_cloudwatch), ("Secrets Manager", sc_secrets),
    ("Redshift", sc_redshift), ("ECR", sc_ecr), ("SQS", sc_sqs), ("SNS", sc_sns),
    ("KMS", sc_kms), ("Step Functions", sc_stepfunctions), ("Glue", sc_glue),
    ("API Gateway", sc_apigateway), ("EFS", sc_efs), ("Kinesis", sc_kinesis),
    ("MSK", sc_msk), ("Amazon MQ", sc_mq), ("Transfer Family", sc_transfer),
]

# Global services (billed under region "global"): scanned once via us-east-1
GLOBAL_SCANNERS = [("CloudFront", sc_cloudfront), ("Route 53", sc_route53)]
GLOBAL_REGIONS = ("global", "NoRegion")


def merge_tagging_api(s, only_services=None):
    """Fill tags on scanned resources and add any other tagged resource."""
    tg = s.client("resourcegroupstaggingapi")
    added = 0
    for p in pages(tg, "get_resources", ResourcesPerPage=100):
        for m in p.get("ResourceTagMappingList", []):
            arn = m["ResourceARN"]
            tags = tags_of(m.get("Tags"))
            if arn in s.items:
                if tags and not s.items[arn]["Tags"]:
                    s.items[arn]["Tags"] = tags
                continue
            svc, _, kind, rid = parse_arn(arn)
            if only_services and svc not in only_services:
                continue
            if svc == "ec2" and kind not in BILLABLE_EC2:
                continue
            s.add(arn, tags.get("Name") or rid, "unknown", tags)
            added += 1
    return added


def scan_region(profile, region, acct, partition):
    session = boto3.Session(profile_name=profile, region_name=region)
    s = Scan(session, region, acct, partition)
    log(f"[Inventory] {region}: scanning...")
    for name, fn in SCANNERS:
        if STOP.is_set():
            break
        t0, before = time.monotonic(), len(s.items)
        try:
            fn(s)
            log(f"   [{region}] {name}: {len(s.items) - before} found "
                f"({time.monotonic() - t0:.1f}s)", verbose_only=True)
        except Exception as exc:
            log(f"[WARN] {region} {name}: {short(exc)}")
    try:
        added = merge_tagging_api(s)
        log(f"   [{region}] tagging API: +{added} extra tagged resources", verbose_only=True)
    except Exception as exc:
        log(f"[WARN] {region} tagging API failed (tags may be incomplete): {short(exc)}")
    log(f"[Inventory] {region}: {len(s.items)} resources")
    return list(s.items.values())


def scan_global(profile, acct, partition):
    """CloudFront / Route 53 live outside regions; scan once and file under 'global'."""
    session = boto3.Session(profile_name=profile, region_name="us-east-1")
    s = Scan(session, "us-east-1", acct, partition)
    log("[Inventory] global services: scanning...")
    for name, fn in GLOBAL_SCANNERS:
        try:
            fn(s)
        except Exception as exc:
            log(f"[WARN] global {name}: {short(exc)}")
    try:
        merge_tagging_api(s, only_services={"cloudfront", "route53"})
    except Exception as exc:
        log(f"[WARN] global tagging API failed (tags may be incomplete): {short(exc)}")
    items = list(s.items.values())
    for it in items:
        it["Region"] = "global"
    log(f"[Inventory] global: {len(items)} resources")
    return items


def scan_s3(session, home_region, acct, target_regions):
    """S3 is global in the API: list once, place each bucket in its own region."""
    out = []
    try:
        s3 = get_client(session, "s3", "us-east-1")
        buckets = s3.list_buckets().get("Buckets", [])
        log(f"[Inventory] S3: {len(buckets)} buckets, resolving regions...")
        for b in buckets:
            if STOP.is_set():
                break
            region = "us-east-1"
            try:
                loc = s3.get_bucket_location(Bucket=b["Name"]).get("LocationConstraint")
                if loc:
                    region = "eu-west-1" if loc == "EU" else loc
            except (ClientError, BotoCoreError):
                continue
            if region not in target_regions:
                continue
            out.append({
                "Key": f"arn:aws:s3:::{b['Name']}", "ARN": f"arn:aws:s3:::{b['Name']}",
                "Region": region, "Svc": "s3", "Kind": "bucket", "ID": b["Name"],
                "Name": b["Name"], "State": "active", "Tags": {},
                "Created": b.get("CreationDate"), "CostService": None, "Weight": 1.0,
                "Attribution": "Not checked", "CreatedBy": "", "PrincipalType": "",
                "ViaRole": "", "CreatorARN": "", "CreatedAt": "",
            })
    except Exception as exc:
        log(f"[WARN] S3 scan: {short(exc)}")
    return out


def merge_items(batches):
    merged = {}
    for batch in batches:
        for it in batch:
            cur = merged.get(it["Key"])
            if not cur:
                merged[it["Key"]] = it
                continue
            if it["Tags"] and not cur["Tags"]:
                cur["Tags"] = it["Tags"]
            if cur["State"] == "unknown" and it["State"] != "unknown":
                cur["State"] = it["State"]
            if not cur["Created"] and it["Created"]:
                cur["Created"] = it["Created"]
    return list(merged.values())


def assign_cost_services(items, costs):
    by_region = defaultdict(list)
    for (region, svc), c in costs.items():
        by_region[region].append((svc, c, region))
    for it in items:
        regs = list(GLOBAL_REGIONS) if it["Region"] in GLOBAL_REGIONS else [it["Region"]]
        pool = [x for r in regs for x in by_region.get(r, [])]
        for key in cost_keys_for(it["Svc"], it["Kind"]):
            cands = [(c, svc, r) for svc, c, r in pool if key in svc.lower()
                     and not (it["Svc"] == "ecs" and "kubernetes" in svc.lower())]
            if cands:
                _, it["CostService"], it["Region"] = max(cands)
                break


# ============================================================
# CLOUDTRAIL: WHO CREATED IT
# ============================================================

CREATE_RE = re.compile(r"^(Create|RunInstances|Allocate|Import|Launch|Provision|Register|"
                       r"Copy|Restore)")


def who(identity):
    t = identity.get("type", "Unknown")
    arn = identity.get("arn", "")
    if t == "IAMUser":
        return identity.get("userName") or arn.split("/")[-1], "IAM User", ""
    if t == "AssumedRole":
        issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})
        parts = arn.split("/")
        role = issuer.get("userName") or (parts[-2] if len(parts) >= 2 else "")
        return parts[-1], "Assumed Role", role
    if t == "Root":
        return "root", "Root", ""
    if t == "AWSService":
        return identity.get("invokedBy") or "AWS Service", "AWS Service", ""
    return identity.get("userName") or arn or t, t, ""


class Pacer:
    """LookupEvents allows ~2 requests/second per region."""
    def __init__(self, gap=0.55):
        self.gap, self.last = gap, 0.0

    def __call__(self):
        wait = self.gap - (time.monotonic() - self.last)
        if wait > 0:
            time.sleep(wait)
        self.last = time.monotonic()


def lookup_creator(ct, it, start, end, pacer, max_pages):
    keys = []
    for k in (it["ID"], it["ARN"]):
        if k and k not in keys:
            keys.append(k)
    events = []
    for key in keys[:2]:
        token, n = None, 0
        while n < max_pages:
            pacer()
            kw = {"LookupAttributes": [{"AttributeKey": "ResourceName",
                                        "AttributeValue": key}],
                  "StartTime": start, "EndTime": end, "MaxResults": 50}
            if token:
                kw["NextToken"] = token
            resp = ct.lookup_events(**kw)
            n += 1
            for e in resp.get("Events", []):
                try:
                    events.append((e["EventTime"], json.loads(e["CloudTrailEvent"])))
                except (KeyError, ValueError, TypeError):
                    continue
            token = resp.get("NextToken")
            if not token:
                break
        if events:
            break
    if not events:
        return None
    events.sort(key=lambda x: x[0])
    ok = [x for x in events if not x[1].get("errorCode")]
    created = [x for x in ok if CREATE_RE.match(x[1].get("eventName", ""))]
    if created:
        return "Creator confirmed", created[0][1]
    writes = [x for x in ok if x[1].get("readOnly") is False]
    if writes:
        return "Earliest write activity (create event not in window)", writes[0][1]
    return None


def creators_for_region(profile, region, its, start, end, budget, max_pages):
    api_region = "us-east-1" if region in GLOBAL_REGIONS else region
    session = boto3.Session(profile_name=profile, region_name=api_region)
    ct = get_client(session, "cloudtrail", api_region)
    pacer, t0, done = Pacer(), time.monotonic(), 0
    its = sorted(its, key=lambda i: bool(i["Tags"]))   # untagged first
    log(f"[CloudTrail] {region}: looking up {len(its)} resources "
        f"({'no time limit' if not budget else f'budget {budget}s'})")
    for it in its:
        if STOP.is_set():
            break
        if budget and time.monotonic() - t0 > budget:
            log(f"[CloudTrail] {region}: time budget reached; remaining resources unchecked")
            break
        try:
            res = lookup_creator(ct, it, start, end, pacer, max_pages)
        except Exception as exc:
            it["Attribution"] = f"Lookup error: {short(exc, 80)}"
            continue
        done += 1
        if done % 10 == 0:
            log(f"   [{region}] CloudTrail progress: {done}/{len(its)} resources checked")
        if not res:
            it["Attribution"] = "Not found (older than 90 days or not logged)"
            it["CreatedBy"] = "Unknown"
            continue
        label, d = res
        name, ptype, role = who(d.get("userIdentity", {}))
        it.update({"Attribution": label, "CreatedBy": name, "PrincipalType": ptype,
                   "ViaRole": role, "CreatorARN": d.get("userIdentity", {}).get("arn", ""),
                   "CreatedAt": d.get("eventTime", "")})
        log(f"   [{region}] {it['Svc']}:{it['Kind']} {it['ID']} -> {name}", verbose_only=True)
    log(f"[CloudTrail] {region}: {done} lookups in {time.monotonic() - t0:.0f}s")


def run_creator_lookups(profile, items, days, budget, workers, max_pages):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    by_region = defaultdict(list)
    for it in items:
        if it["CostService"]:
            by_region[it["Region"]].append(it)
    if not by_region:
        return
    log(f"\n[CloudTrail] Creator lookup in {len(by_region)} region(s)...")
    ex = ThreadPoolExecutor(max_workers=max(1, workers))
    futs = {ex.submit(creators_for_region, profile, r, its, start, end, budget, max_pages): r
            for r, its in by_region.items()}
    try:
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as exc:
                log(f"[WARN] CloudTrail {futs[f]}: {short(exc)}")
    except KeyboardInterrupt:
        STOP.set()
        log("\n[Interrupted] stopping CloudTrail lookups, keeping what was found...")
    finally:
        ex.shutdown(wait=False, cancel_futures=True)


# ============================================================
# REPORT BUILDING
# ============================================================

def build_report(costs, usage, items, ascending, required_tags, exact_index):
    by_svc = defaultdict(list)
    for it in items:
        if it["CostService"]:
            by_svc[(it["Region"], it["CostService"])].append(it)

    region_total = defaultdict(float)
    for (region, _), c in costs.items():
        region_total[region] += c

    def order(key):
        region, _ = key
        c = costs[key]
        return (-region_total[region], region, c if ascending else -c)

    summary, details, untagged, usage_rows = [], [], [], []
    for key in sorted(costs, key=order):
        region, svc = key
        cost = costs[key]
        its = by_svc.get(key, [])
        item_costs, extras, unalloc = allocate_costs(
            its, cost, usage.get(key, []), exact_index.get(key), service_name=svc)
        allocated = round(sum(c for c, _ in item_costs.values()) + sum(c for _, c in extras), 4)

        counts = defaultdict(int)
        for it in its:
            counts[normalize_status(it["State"])] += 1
        creators = []
        for it in its:
            c = it["CreatedBy"]
            if c and c != "Unknown":
                lab = f"{c} (via {it['ViaRole']})" if it["ViaRole"] else c
                if lab not in creators:
                    creators.append(lab)
        n_untagged = sum(1 for it in its if not it["Tags"])

        top_usage = "; ".join(f"{u} (${c:,.2f})" for u, c in usage.get(key, [])[:3])
        n_vpc_only = sum(1 for it in its if it.get("Kind") == "vpc")
        summary.append({
            "Region": region, "Service": svc, "Cost (USD)": cost,
            "Resources Found": len(its),
            "Resource Counts": inventory_breakdown(its),
            "VPC Count": n_vpc_only if is_vpc_billing_service(svc) else "",
            "Allocated to Resources (USD)": allocated,
            "Unallocated (USD)": round(max(unalloc, 0.0), 4),
            "Untagged Resources": n_untagged,
            "Status": format_status_summary(counts),
            "Created By (IAM user / session)": "; ".join(creators),
            "Top Usage Types": top_usage,
        })

        for ut, c in usage.get(key, []):
            usage_rows.append({"Region": region, "Service": svc, "Usage Type": ut,
                               "Cost (USD)": c,
                               "Share of Service (%)": round(c / cost * 100, 1) if cost else 0.0})

        group = []   # (sort key, row)
        for it in its:
            res_cost, _ = item_costs[it["Key"]]
            cat = resource_category(it)
            row = strip_detail_columns({
                "Region": region, "Service": svc, "Service Total (USD)": cost,
                "Resource Cost (USD)": res_cost,
                "Type": cat,
                "Resource Type": f"{it['Svc']}:{it['Kind']}", "Resource ID": it["ID"],
                "Resource Name": it["Name"], "Resource": resource_display(it),
                "Status": normalize_status(it["State"]),
                "Raw State": it["State"],
                "Created By (IAM user / session)": it["CreatedBy"],
                "Principal Type": it["PrincipalType"], "Via Role": it["ViaRole"],
                "Created At": it["CreatedAt"] or fmt_dt(it["Created"]),
                "Attribution": it["Attribution"],
                "Tagged?": "Yes" if it["Tags"] else "No",
                "Tag Count": len(it["Tags"]), "Tags": tag_string(it["Tags"]),
            })
            if required_tags:
                row["Missing Required Tags"] = ", ".join(
                    t for t in required_tags if t not in it["Tags"])
            group.append(((CATEGORY_SORT.get(cat, 999), cat, bool(it["Tags"]), -res_cost), row))
            if not it["Tags"] or (required_tags and row.get("Missing Required Tags")):
                untagged.append(dict(row))

        for rid, c in extras:
            group.append(((998, "Billing-only", 2, -c), strip_detail_columns({
                "Region": region, "Service": svc, "Service Total (USD)": cost,
                "Resource Cost (USD)": c,
                "Type": "Billing-only (not in scan)",
                "Resource Type": "billing-only", "Resource ID": rid,
                "Resource Name": "Billed by AWS but not in the resource scan "
                                 "(deleted or unscanned resource type)",
                "Resource": rid, "Status": "Status Unknown", "Raw State": "",
                "Tagged?": "Not scanned", "Tag Count": 0, "Tags": "",
            })))

        if unalloc >= 0.0001:
            group.append(((999, "Unallocated", 3, 0), strip_detail_columns({
                "Region": region, "Service": svc, "Service Total (USD)": cost,
                "Resource Cost (USD)": unalloc,
                "Type": "Unallocated",
                "Resource Type": "unallocated", "Resource ID": "-",
                "Resource Name": "Unallocated (usage not tied to a single resource in scan)",
                "Resource": "(unallocated)", "Status": "", "Raw State": "",
                "Tagged?": "", "Tag Count": 0, "Tags": "",
            })))

        group.sort(key=lambda t: t[0])
        block = collapse_service_header_rows([strip_detail_columns(dict(row)) for _, row in group])
        details.extend(block)

        row_sum = round(sum(r.get("Resource Cost (USD)", 0) or 0 for r in block), 4)
        if its and abs(row_sum - cost) > 0.02:
            log(f"[WARN] {region} · {svc[:40]}: service bill ${cost:,.2f} vs "
                f"resource rows ${row_sum:,.2f}", verbose_only=True)

    return summary, details, untagged, usage_rows


def write_excel(path, sheets):
    log("\n[Report] Writing Excel...")
    with pd.ExcelWriter(path, engine="openpyxl") as writer:
        for name, rows in sheets:
            df = pd.DataFrame(rows)
            if df.empty:
                df = pd.DataFrame({"Information": ["No data."]})
            df.to_excel(writer, sheet_name=name[:31], index=False)
            log(f"   sheet: {name} ({len(rows)} rows)")
        for ws in writer.sheets.values():
            ws.freeze_panes = "A2"
            ws.auto_filter.ref = ws.dimensions
            for col in ws.iter_cols():
                header = str(col[0].value or "")
                if "(USD)" in header:
                    for c in col[1:]:
                        if isinstance(c.value, (int, float)):
                            c.number_format = "$#,##0.0000"
                if "(%)" in header:
                    for c in col[1:]:
                        if isinstance(c.value, (int, float)):
                            c.number_format = "0.0"
                width = max((len(str(c.value)) for c in col if c.value is not None), default=8)
                ws.column_dimensions[col[0].column_letter].width = min(width + 3, 60)
    log(f"[SUCCESS] Report written: {path}")


def print_console_summary(summary):
    log("\n" + "=" * 110)
    log(f"{'REGION':<16}{'SERVICE':<46}{'COST USD':>11}{'UNALLOC':>10}{'UNTAGGED':>10}  CREATED BY")
    log("=" * 110)
    for r in summary:
        log(f"{r['Region']:<16}{r['Service'][:44]:<46}{r['Cost (USD)']:>11,.2f}"
            f"{r['Unallocated (USD)']:>10,.2f}{r['Untagged Resources']:>10}  "
            f"{r['Created By (IAM user / session)'][:40]}")


# ============================================================
# MAIN
# ============================================================

def main():
    global VERBOSE
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    ap = argparse.ArgumentParser(description="AWS cleanup audit (billed + untagged resources)")
    ap.add_argument("--profile", default=os.getenv("AWS_PROFILE", DEFAULT_PROFILE))
    ap.add_argument("--region", default=DEFAULT_REGION, help="home region for STS")
    ap.add_argument("--regions", help="comma list; default = every region that has cost")
    ap.add_argument("--days", type=int, default=DEFAULT_DAYS,
                    help="billing window (1-90); exact per-resource cost needs <= 14")
    ap.add_argument("--min-cost", type=float, default=0.0,
                    help="keep only services with cost above this (default: anything > $0)")
    ap.add_argument("--ascending", action="store_true",
                    help="sort services low->high within each region (default high->low)")
    ap.add_argument("--required-tags", default="",
                    help="comma list, e.g. Owner,Environment; adds a 'Missing Required Tags' column")
    ap.add_argument("--output", default="AWS_Cleanup_Audit.xlsx")
    ap.add_argument("--skip-cloudtrail", action="store_true")
    ap.add_argument("--region-budget", type=int, default=0,
                    help="max seconds of CloudTrail lookups per region (default 0 = no limit)")
    ap.add_argument("--max-pages", type=int, default=20,
                    help="max CloudTrail pages (50 events each) per resource lookup")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose

    if not 1 <= args.days <= 90:
        ap.error("--days must be between 1 and 90")
    required_tags = [t.strip() for t in args.required_tags.split(",") if t.strip()]

    log("=" * 40)
    log("      AWS CLEANUP AUDIT")
    log("=" * 40)

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        ident = get_client(session, "sts", args.region).get_caller_identity()
    except (ClientError, BotoCoreError) as exc:
        log(f"AWS authentication failed: {short(exc, 300)}")
        log("If you use an MFA session profile, refresh the temporary credentials and retry.")
        return
    acct, partition = ident["Account"], ident["Arn"].split(":")[1]
    log(f"Account {acct} | {ident['Arn']}")

    end_d = datetime.now(timezone.utc).date() + timedelta(days=1)   # end is exclusive
    start_d = end_d - timedelta(days=args.days + 1)
    start, end = start_d.isoformat(), end_d.isoformat()
    log(f"Billing window: {start} -> {end}")

    # 1. Billing (exact service totals) + exact per-resource costs when available
    try:
        ce = get_client(session, "ce", "us-east-1")
        costs, usage = get_costs(ce, start, end, args.min_cost)
        if not costs:
            log("No services with cost found for this window.")
            return
        if args.days <= 14:
            raw_res_costs = fetch_resource_costs(ce, start, end, costs.keys())
        else:
            raw_res_costs = {}
            log("\n[Billing] --days is above 14: Cost Explorer resource-level data only covers "
                "the last 14 days, so per-resource costs are ESTIMATED from usage types. "
                "Use --days 14 (or less) for exact per-resource costs.")
        exact_index = build_exact_index(raw_res_costs)
    except (ClientError, BotoCoreError) as exc:
        log(f"Cost Explorer failed: {short(exc, 300)}")
        return

    items = []
    try:
        # 2. Resource scan, only where money was spent
        if args.regions:
            regions = [r.strip() for r in args.regions.split(",") if r.strip()]
        else:
            regions = sorted({r for (r, _) in costs
                              if re.match(r"^[a-z]{2}(-[a-z]+)+-\d$", r)})
        log(f"\nRegions with cost: {', '.join(regions) or '(none - only global services)'}")

        batches = []
        ex = ThreadPoolExecutor(max_workers=max(1, args.workers))
        futs = {ex.submit(scan_region, args.profile, r, acct, partition): r for r in regions}
        try:
            for f in as_completed(futs):
                try:
                    batches.append(f.result())
                except Exception as exc:
                    log(f"[WARN] scan {futs[f]} failed: {short(exc)}")
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        if any(r in GLOBAL_REGIONS for (r, _) in costs):
            batches.append(scan_global(args.profile, acct, partition))
        batches.append(scan_s3(session, args.region, acct, set(regions)))
        items = merge_items(batches)
        assign_cost_services(items, costs)
        billed = [i for i in items if i["CostService"]]
        log(f"\n[Inventory] {len(items)} resources total, {len(billed)} map to a billed service, "
            f"{sum(1 for i in billed if not i['Tags'])} of those are untagged")

        # 3. Who created them
        if not args.skip_cloudtrail:
            run_creator_lookups(args.profile, items, 90, args.region_budget,
                                args.workers, args.max_pages)
        else:
            log("\n[CloudTrail] skipped")
    except KeyboardInterrupt:
        STOP.set()
        log("\n[Interrupted] writing report with what was collected so far...")

    # 4. Report (always runs)
    summary, details, untagged, usage_rows = build_report(
        costs, usage, items, args.ascending, required_tags, exact_index)
    print_console_summary(summary)
    no_res = [r for r in summary if r["Resources Found"] == 0]
    if no_res:
        log("\nBilled but NO resources found (usage-based, already deleted, or a service "
            "this script does not scan - check manually):")
        for r in no_res:
            log(f"   {r['Region']:<16}{r['Service'][:60]:<62}${r['Cost (USD)']:,.2f}")
    write_excel(args.output, [
        ("Region-Service Summary", summary),
        ("Resource Details", details),
        ("Untagged Resources", untagged),
        ("Usage Breakdown", usage_rows),
    ])

    total = sum(r["Cost (USD)"] for r in summary)
    log(f"\nBilled services:      {len(summary)}   (total ${total:,.2f})")
    log(f"Resource rows:        {len(details)}")
    log(f"Untagged / to review: {len(untagged)}")
    log(f"Excel file:           {args.output}")
    log("\nHow to read the costs: 'Cost (USD)' per service is the exact AWS bill. 'Resource Cost "
        "(USD)' is exact when Cost Basis says Exact (Cost Explorer resource-level data), otherwise "
        "an estimate that splits each usage type across matching resources. 'Unallocated' is the "
        "part of a service's bill that cannot be tied to one resource, so each service's rows "
        "always add up to its total. CloudTrail keeps 90 days, so older resources show creator "
        "'Unknown'.")


if __name__ == "__main__":
    main()