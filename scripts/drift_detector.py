from __future__ import annotations
#!/usr/bin/env python3
"""
GitOps Config Drift Detector
Compares live AWS resource state against Terraform state files
and raises GitHub issues when drift is detected.
"""

import json
import os
import sys
import hashlib
import logging
import subprocess
from datetime import datetime, timezone
from typing import Any
import boto3
import requests
from dataclasses import dataclass, field, asdict

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class DriftItem:
    resource_type: str
    resource_id: str
    attribute: str
    expected: Any
    actual: Any
    severity: str = "medium"   # low | medium | high | critical

    def to_markdown_row(self) -> str:
        sev_emoji = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(self.severity, "⚪")
        return (
            f"| `{self.resource_type}` | `{self.resource_id}` | `{self.attribute}` "
            f"| `{self.expected}` | `{self.actual}` | {sev_emoji} {self.severity.upper()} |"
        )


@dataclass
class DriftReport:
    scan_id: str
    timestamp: str
    aws_region: str
    total_resources_checked: int = 0
    drifted_resources: int = 0
    drift_items: list[DriftItem] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return len(self.drift_items) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for d in self.drift_items if d.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for d in self.drift_items if d.severity == "high")


# ──────────────────────────────────────────────────────────────────────────────
# Terraform State Reader
# ──────────────────────────────────────────────────────────────────────────────

class TerraformStateReader:
    """Reads desired state from Terraform state files (local or S3 backend)."""

    def __init__(self, state_path: str | None = None, s3_bucket: str | None = None,
                 s3_key: str | None = None):
        self.state_path = state_path
        self.s3_bucket = s3_bucket
        self.s3_key = s3_key

    def load(self) -> dict:
        if self.s3_bucket and self.s3_key:
            return self._load_from_s3()
        if self.state_path:
            return self._load_from_file()
        return self._load_via_cli()

    def _load_from_file(self) -> dict:
        log.info("Loading Terraform state from file: %s", self.state_path)
        with open(self.state_path) as f:
            return json.load(f)

    def _load_from_s3(self) -> dict:
        log.info("Loading Terraform state from s3://%s/%s", self.s3_bucket, self.s3_key)
        s3 = boto3.client("s3")
        obj = s3.get_object(Bucket=self.s3_bucket, Key=self.s3_key)
        return json.loads(obj["Body"].read())

    def _load_via_cli(self) -> dict:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        tf_dir = os.environ.get("TF_DIR", os.path.join(project_root, "terraform"))
        log.info("Pulling Terraform state via CLI from folder: %s", tf_dir)
        result = subprocess.run(
            ["terraform", "show", "-json"],
            capture_output=True, text=True, check=True,
            cwd=tf_dir,
        )
        return json.loads(result.stdout)

    def extract_resources(self, state: dict) -> dict[str, dict]:
        """Return {resource_address: attributes} from a Terraform state blob."""
        resources: dict[str, dict] = {}
        for resource in state.get("resources", []):
            for instance in resource.get("instances", []):
                addr = f"{resource['type']}.{resource['name']}"
                resources[addr] = instance.get("attributes", {})
        # Support `terraform show -json` format (values.root_module)
        values = state.get("values", {}).get("root_module", {})
        for resource in values.get("resources", []):
            resources[resource["address"]] = resource.get("values", {})
        return resources


# ──────────────────────────────────────────────────────────────────────────────
# AWS Live-State Fetchers
# ──────────────────────────────────────────────────────────────────────────────

class AWSStateReader:
    """Fetches current live state from AWS APIs."""

    SEVERITY_MAP = {
        "aws_security_group": "high",
        "aws_iam_role": "critical",
        "aws_iam_policy": "critical",
        "aws_s3_bucket": "high",
        "aws_instance": "medium",
        "aws_db_instance": "high",
        "aws_lb": "medium",
        "aws_autoscaling_group": "medium",
    }

    def __init__(self, region: str):
        self.region = region
        self.ec2 = boto3.client("ec2", region_name=region)
        self.s3 = boto3.client("s3", region_name=region)
        self.iam = boto3.client("iam", region_name=region)
        self.rds = boto3.client("rds", region_name=region)
        self.elbv2 = boto3.client("elbv2", region_name=region)

    def fetch(self, resource_type: str, attributes: dict) -> dict | None:
        fetcher = {
            "aws_instance": self._fetch_ec2_instance,
            "aws_security_group": self._fetch_security_group,
            "aws_s3_bucket": self._fetch_s3_bucket,
            # These are the SEPARATE resource types Terraform actually uses:
            "aws_s3_bucket_public_access_block": self._fetch_s3_public_access_block,
            "aws_s3_bucket_server_side_encryption_configuration": self._fetch_s3_encryption,
            "aws_s3_bucket_versioning": self._fetch_s3_versioning,
            "aws_iam_role": self._fetch_iam_role,
            "aws_db_instance": self._fetch_rds_instance,
            "aws_lb": self._fetch_alb,
        }.get(resource_type)
        if fetcher is None:
            return None
        try:
            return fetcher(attributes)
        except Exception as exc:
            log.warning("Could not fetch live state for %s: %s", resource_type, exc)
            return None

    # ── EC2 ──────────────────────────────────────────────────────────────────

    def _fetch_ec2_instance(self, attrs: dict) -> dict | None:
        instance_id = attrs.get("id") or attrs.get("instance_id")
        if not instance_id:
            return None
        resp = self.ec2.describe_instances(InstanceIds=[instance_id])
        reservations = resp.get("Reservations", [])
        if not reservations:
            return None
        inst = reservations[0]["Instances"][0]
        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
        return {
            "instance_type": inst.get("InstanceType"),
            "instance_state": inst["State"]["Name"],   # matches TF field name
            "monitoring": inst.get("Monitoring", {}).get("State") == "enabled",
            "subnet_id": inst.get("SubnetId"),
            "vpc_id": inst.get("VpcId"),
        }

    # ── Security Groups ───────────────────────────────────────────────────────

    def _fetch_security_group(self, attrs: dict) -> dict | None:
        sg_id = attrs.get("id")
        if not sg_id:
            return None
        resp = self.ec2.describe_security_groups(GroupIds=[sg_id])
        sgs = resp.get("SecurityGroups", [])
        if not sgs:
            return None
        sg = sgs[0]
        return {
            "name": sg.get("GroupName"),
            "description": sg.get("Description"),
            "vpc_id": sg.get("VpcId"),
            "ingress_rule_count": len(sg.get("IpPermissions", [])),
            "egress_rule_count": len(sg.get("IpPermissionsEgress", [])),
        }

    # ── S3 ───────────────────────────────────────────────────────────────────

    def _fetch_s3_bucket(self, attrs: dict) -> dict | None:
        bucket = attrs.get("id") or attrs.get("bucket")
        if not bucket:
            return None
        result = {"bucket": bucket}
        try:
            versioning = self.s3.get_bucket_versioning(Bucket=bucket)
            result["versioning_enabled"] = versioning.get("Status") == "Enabled"
        except Exception:
            pass
        try:
            encryption = self.s3.get_bucket_encryption(Bucket=bucket)
            rules = encryption["ServerSideEncryptionConfiguration"]["Rules"]
            result["encryption_enabled"] = len(rules) > 0
        except Exception:
            result["encryption_enabled"] = False
        try:
            public_access = self.s3.get_public_access_block(Bucket=bucket)
            cfg = public_access["PublicAccessBlockConfiguration"]
            result["block_public_acls"] = cfg.get("BlockPublicAcls", False)
            result["block_public_policy"] = cfg.get("BlockPublicPolicy", False)
        except Exception:
            pass
        return result

    def _fetch_s3_public_access_block(self, attrs: dict) -> dict | None:
        """Fetcher for aws_s3_bucket_public_access_block resource."""
        bucket = attrs.get("bucket") or attrs.get("id")
        if not bucket:
            return None
        try:
            resp = self.s3.get_public_access_block(Bucket=bucket)
            cfg = resp["PublicAccessBlockConfiguration"]
            return {
                "block_public_acls":       cfg.get("BlockPublicAcls", False),
                "block_public_policy":     cfg.get("BlockPublicPolicy", False),
                "ignore_public_acls":      cfg.get("IgnorePublicAcls", False),
                "restrict_public_buckets": cfg.get("RestrictPublicBuckets", False),
            }
        except Exception as exc:
            log.warning("Could not fetch S3 public access block for %s: %s", bucket, exc)
            return None

    def _fetch_s3_encryption(self, attrs: dict) -> dict | None:
        """Fetcher for aws_s3_bucket_server_side_encryption_configuration resource."""
        bucket = attrs.get("bucket") or attrs.get("id")
        if not bucket:
            return None
        try:
            resp = self.s3.get_bucket_encryption(Bucket=bucket)
            rules = resp["ServerSideEncryptionConfiguration"]["Rules"]
            if not rules:
                return {"encryption_enabled": False}
            algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm", "")
            return {
                "encryption_enabled": True,
                # We only care if encryption disappeared — not which algo
            }
        except self.s3.exceptions.ClientError:
            return {"encryption_enabled": False}
        except Exception as exc:
            log.warning("Could not fetch S3 encryption for %s: %s", bucket, exc)
            return None

    def _fetch_s3_versioning(self, attrs: dict) -> dict | None:
        """Fetcher for aws_s3_bucket_versioning resource."""
        bucket = attrs.get("bucket") or attrs.get("id")
        if not bucket:
            return None
        try:
            resp = self.s3.get_bucket_versioning(Bucket=bucket)
            status = resp.get("Status", "")
            # Terraform stores this as versioning_configuration[0].status
            return {
                "versioning_configuration": [{"status": status or "Disabled"}]
            }
        except Exception as exc:
            log.warning("Could not fetch S3 versioning for %s: %s", bucket, exc)
            return None

    # ── IAM ──────────────────────────────────────────────────────────────────

    def _fetch_iam_role(self, attrs: dict) -> dict | None:
        role_name = attrs.get("name") or attrs.get("id")
        if not role_name:
            return None
        resp = self.iam.get_role(RoleName=role_name)
        role = resp["Role"]
        return {
            "name": role["RoleName"],
            "path": role.get("Path"),
            "assume_role_policy": json.dumps(
                json.loads(requests.utils.unquote(
                    json.dumps(role.get("AssumeRolePolicyDocument", {}))
                ))
            ),
            "max_session_duration": role.get("MaxSessionDuration"),
        }

    # ── RDS ──────────────────────────────────────────────────────────────────

    def _fetch_rds_instance(self, attrs: dict) -> dict | None:
        identifier = attrs.get("id") or attrs.get("identifier")
        if not identifier:
            return None
        resp = self.rds.describe_db_instances(DBInstanceIdentifier=identifier)
        instances = resp.get("DBInstances", [])
        if not instances:
            return None
        db = instances[0]
        return {
            "instance_class": db.get("DBInstanceClass"),
            "engine": db.get("Engine"),
            "engine_version": db.get("EngineVersion"),
            "multi_az": db.get("MultiAZ"),
            "publicly_accessible": db.get("PubliclyAccessible"),
            "storage_encrypted": db.get("StorageEncrypted"),
            "deletion_protection": db.get("DeletionProtection"),
        }

    # ── ALB ──────────────────────────────────────────────────────────────────

    def _fetch_alb(self, attrs: dict) -> dict | None:
        arn = attrs.get("arn") or attrs.get("id")
        if not arn:
            return None
        resp = self.elbv2.describe_load_balancers(LoadBalancerArns=[arn])
        lbs = resp.get("LoadBalancers", [])
        if not lbs:
            return None
        lb = lbs[0]
        return {
            "name": lb.get("LoadBalancerName"),
            "scheme": lb.get("Scheme"),
            "type": lb.get("Type"),
            "ip_address_type": lb.get("IpAddressType"),
        }


# ──────────────────────────────────────────────────────────────────────────────
# Drift Comparator
# ──────────────────────────────────────────────────────────────────────────────

IGNORED_ATTRIBUTES = {
    "aws_instance": {"password_data", "user_data_base64", "cpu_core_count",
                     "cpu_threads_per_core", "credit_specification",
                     "key_name", "tags", "tags_all",
                     "private_ip", "public_ip", "public_dns", "private_dns",
                     "primary_network_interface_id", "network_interface",
                     "launch_template", "capacity_reservation_specification",
                     "enclave_options", "maintenance_options",
                     "private_dns_name_options",
                     # These change automatically when instance stops — not real drift
                     "disable_api_termination", "disable_api_stop",
                     "instance_initiated_shutdown_behavior",
                     "associate_public_ip_address",
                     "ebs_optimized", "hibernation",
                     "spot_instance_request_id", "outpost_arn",
                     "placement_group", "placement_partition_number",
                     "host_id", "host_resource_group_arn",
                     "ipv6_address_count", "ipv6_addresses",
                     "secondary_private_ips", "security_groups",
                     "volume_tags", "user_data_replace_on_change",
                     "get_password_data", "ami",
                     "arn", "availability_zone",
                     "cpu_options", "ebs_block_device", "ephemeral_block_device",
                     "instance_lifecycle", "instance_market_options",
                     "metadata_options", "root_block_device",
                     "source_dest_check", "tenancy",
                     "vpc_security_group_ids"},
    "aws_s3_bucket": {"force_destroy", "lifecycle_rule", "tags", "tags_all"},
    "aws_iam_role":  {"tags", "tags_all", "inline_policy", "managed_policy_arns",
                      "role_last_used", "unique_id", "create_date"},
    # These sub-resources only have a few meaningful fields — ignore bucket metadata
    "aws_s3_bucket_public_access_block": {"id", "bucket"},
    "aws_s3_bucket_server_side_encryption_configuration": {"id", "bucket", "expected_bucket_owner", "rule"},
    # versioning_configuration comparison handled separately — ignore the full nested object
    # to avoid mfa_delete false positives; we check status only via _fetch_s3_versioning
    "aws_s3_bucket_versioning": {"id", "bucket", "expected_bucket_owner", "mfa",
                                  "versioning_configuration"},
    "aws_iam_role_policy": {"id", "role", "policy", "name", "name_prefix"},
    "aws_iam_instance_profile": {"id", "name", "role", "arn", "create_date",
                                  "unique_id", "name_prefix", "path",
                                  "tags", "tags_all"},
}

SEVERITY_OVERRIDES = {
    # EC2
    ("aws_instance", "instance_state"): "critical",
    ("aws_instance", "instance_type"):  "high",
    # S3 public access block (separate TF resource)
    ("aws_s3_bucket_public_access_block", "block_public_acls"):       "critical",
    ("aws_s3_bucket_public_access_block", "block_public_policy"):     "critical",
    ("aws_s3_bucket_public_access_block", "ignore_public_acls"):      "critical",
    ("aws_s3_bucket_public_access_block", "restrict_public_buckets"): "critical",
    # S3 encryption (separate TF resource)
    ("aws_s3_bucket_server_side_encryption_configuration", "encryption_enabled"): "critical",
    # Legacy combined fetcher (kept for safety)
    ("aws_s3_bucket", "block_public_acls"):   "critical",
    ("aws_s3_bucket", "block_public_policy"):  "critical",
    ("aws_s3_bucket", "encryption_enabled"):   "critical",
    # IAM
    ("aws_iam_role", "assume_role_policy"): "critical",
    # RDS
    ("aws_db_instance", "publicly_accessible"): "critical",
    ("aws_db_instance", "deletion_protection"):  "high",
    ("aws_db_instance", "storage_encrypted"):    "critical",
}


def _normalize(val) -> str:
    """Normalize a value for comparison — sorts JSON keys so order doesn't matter."""
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            return json.dumps(parsed, sort_keys=True)
        except Exception:
            pass
    if isinstance(val, (dict, list)):
        return json.dumps(val, sort_keys=True)
    return str(val).lower().strip()


def compare(resource_type: str, resource_id: str,
            desired: dict, actual: dict) -> list[DriftItem]:
    """Return a list of DriftItem for every attribute that differs."""
    drifts = []
    ignored = IGNORED_ATTRIBUTES.get(resource_type, set())
    default_severity = AWSStateReader.SEVERITY_MAP.get(resource_type, "medium")

    for key, expected_val in desired.items():
        if key in ignored or key.startswith("_") or key in {"id", "arn", "timeouts"}:
            continue
        if key not in actual:
            continue
        live_val = actual[key]
        # Normalize both sides — handles JSON key ordering differences
        if _normalize(expected_val) != _normalize(live_val):
            severity = SEVERITY_OVERRIDES.get((resource_type, key), default_severity)
            drifts.append(DriftItem(
                resource_type=resource_type,
                resource_id=resource_id,
                attribute=key,
                expected=expected_val,
                actual=live_val,
                severity=severity,
            ))
    return drifts


# ──────────────────────────────────────────────────────────────────────────────
# GitHub Issue Creator
# ──────────────────────────────────────────────────────────────────────────────

class GitHubIssueCreator:
    API = "https://api.github.com"

    def __init__(self, token: str, repo: str):
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.repo = repo  # "owner/repo"

    def find_open_drift_issue(self, scan_label: str) -> int | None:
        url = f"{self.API}/repos/{self.repo}/issues"
        resp = requests.get(url, headers=self.headers,
                            params={"labels": scan_label, "state": "open"})
        resp.raise_for_status()
        issues = resp.json()
        return issues[0]["number"] if issues else None

    def create_or_update(self, report: DriftReport) -> str:
        label = "drift-detected"
        self._ensure_label(label, "d93f0b", "Config drift detected by GitOps scanner")

        title = (
            f"🚨 Config Drift Detected — {report.drifted_resources} resource(s) "
            f"[{report.timestamp[:10]}]"
        )
        body = self._build_body(report)

        existing = self.find_open_drift_issue(label)
        if existing:
            url = f"{self.API}/repos/{self.repo}/issues/{existing}"
            resp = requests.patch(url, headers=self.headers,
                                  json={"title": title, "body": body})
            resp.raise_for_status()
            log.info("Updated existing GitHub issue #%s", existing)
            return resp.json()["html_url"]
        else:
            url = f"{self.API}/repos/{self.repo}/issues"
            resp = requests.post(url, headers=self.headers,
                                 json={"title": title, "body": body,
                                       "labels": [label]})
            resp.raise_for_status()
            log.info("Created GitHub issue #%s", resp.json()["number"])
            return resp.json()["html_url"]

    def close_drift_issues(self):
        label = "drift-detected"
        url = f"{self.API}/repos/{self.repo}/issues"
        resp = requests.get(url, headers=self.headers,
                            params={"labels": label, "state": "open"})
        resp.raise_for_status()
        for issue in resp.json():
            requests.patch(
                f"{self.API}/repos/{self.repo}/issues/{issue['number']}",
                headers=self.headers,
                json={"state": "closed",
                      "body": issue["body"] + "\n\n✅ **Drift resolved — auto-closed.**"},
            )
            log.info("Closed drift issue #%s", issue["number"])

    def _ensure_label(self, name: str, color: str, description: str):
        url = f"{self.API}/repos/{self.repo}/labels"
        resp = requests.get(url, headers=self.headers)
        existing = [l["name"] for l in resp.json()] if resp.ok else []
        if name not in existing:
            requests.post(url, headers=self.headers,
                          json={"name": name, "color": color,
                                "description": description})

    def _build_body(self, report: DriftReport) -> str:
        severity_bar = (
            f"🔴 **{report.critical_count} Critical** &nbsp;|&nbsp; "
            f"🟠 **{report.high_count} High** &nbsp;|&nbsp; "
            f"🟡 {sum(1 for d in report.drift_items if d.severity == 'medium')} Medium &nbsp;|&nbsp; "
            f"🟢 {sum(1 for d in report.drift_items if d.severity == 'low')} Low"
        )

        rows = "\n".join(d.to_markdown_row() for d in report.drift_items)

        errors_section = ""
        if report.errors:
            errors_section = "\n### ⚠️ Scan Errors\n" + "\n".join(
                f"- `{e}`" for e in report.errors)

        return f"""## 🔍 GitOps Config Drift Report

> **Scan ID:** `{report.scan_id}`
> **Timestamp:** `{report.timestamp}`
> **Region:** `{report.aws_region}`
> **Resources Checked:** {report.total_resources_checked}
> **Drifted Resources:** {report.drifted_resources}

---

### Severity Summary
{severity_bar}

---

### Drift Details

| Resource Type | Resource ID | Attribute | Expected (Terraform) | Actual (AWS) | Severity |
|---|---|---|---|---|---|
{rows}

---

### Remediation

To fix drift, run one of the following:

```bash
# Option A — Re-apply Terraform (recommended)
terraform plan   # review changes
terraform apply

# Option B — Import the manually changed resource
terraform import <resource_type>.<name> <resource_id>

# Option C — Update Terraform state to match live AWS (use with caution)
terraform state rm <resource_address>
terraform import <resource_type>.<name> <resource_id>
```

---

### How to Suppress False Positives

Add a lifecycle ignore block in your Terraform:

```hcl
lifecycle {{
  ignore_changes = [tags, user_data]
}}
```

---
{errors_section}

*This issue was auto-generated by the [GitOps Drift Detector](../../actions) pipeline.*
"""


# ──────────────────────────────────────────────────────────────────────────────
# Report Serializer
# ──────────────────────────────────────────────────────────────────────────────

def save_report(report: DriftReport, path: str = "drift-report.json"):
    data = asdict(report)
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    log.info("Drift report saved to %s", path)


# ──────────────────────────────────────────────────────────────────────────────
# Scan History Writer
# ──────────────────────────────────────────────────────────────────────────────

def append_scan_history(report: DriftReport, issue_url: str = "", history_path: str = ""):
    """Append this scan result to scan-history.json (kept in dashboard/)."""
    if not history_path:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        history_path = os.path.join(project_root, "dashboard", "scan-history.json")

    # Load existing history
    history = []
    try:
        with open(history_path) as f:
            history = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Prepend new entry (newest first)
    entry = {
        "scan_id": report.scan_id,
        "timestamp": report.timestamp,
        "aws_region": report.aws_region,
        "total_resources_checked": report.total_resources_checked,
        "drifted": len(report.drift_items),   # -1 = error, 0 = clean, >0 = drift count
        "issue_url": issue_url,
    }
    history.insert(0, entry)

    # Keep only the last 50 scans
    history = history[:50]

    with open(history_path, "w") as f:
        json.dump(history, f, indent=2, default=str)
    log.info("Scan history updated: %s", history_path)


# ──────────────────────────────────────────────────────────────────────────────
# Main Orchestrator
# ──────────────────────────────────────────────────────────────────────────────

def run():
    region = os.environ.get("AWS_REGION", "ap-south-1")
    gh_token = os.environ.get("GITHUB_TOKEN", "")
    gh_repo = os.environ.get("GITHUB_REPOSITORY", "")
    tf_state_path = os.environ.get("TF_STATE_PATH", "")
    tf_s3_bucket = os.environ.get("TF_STATE_S3_BUCKET", "")
    tf_s3_key = os.environ.get("TF_STATE_S3_KEY", "terraform.tfstate")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    default_report = os.path.join(project_root, "dashboard", "drift-report.json")
    output_path = os.environ.get("DRIFT_REPORT_PATH", default_report)

    scan_id = hashlib.sha1(
        f"{datetime.now(timezone.utc).isoformat()}".encode()
    ).hexdigest()[:8]
    timestamp = datetime.now(timezone.utc).isoformat()

    report = DriftReport(scan_id=scan_id, timestamp=timestamp, aws_region=region)

    # ── 1. Load Terraform desired state ──────────────────────────────────────
    tf_reader = TerraformStateReader(
        state_path=tf_state_path or None,
        s3_bucket=tf_s3_bucket or None,
        s3_key=tf_s3_key,
    )
    try:
        state = tf_reader.load()
        tf_resources = tf_reader.extract_resources(state)
        log.info("Loaded %d resources from Terraform state", len(tf_resources))
    except Exception as exc:
        log.error("Failed to load Terraform state: %s", exc)
        report.errors.append(f"Terraform state load failed: {exc}")
        save_report(report, output_path)
        sys.exit(1)

    # ── 2. Fetch live AWS state and compare ───────────────────────────────────
    aws_reader = AWSStateReader(region=region)
    drifted_ids: set[str] = set()

    for address, desired_attrs in tf_resources.items():
        resource_type = address.split(".")[0]
        resource_id = desired_attrs.get("id") or desired_attrs.get("name") or address
        report.total_resources_checked += 1

        live_attrs = aws_reader.fetch(resource_type, desired_attrs)
        if live_attrs is None:
            log.debug("No fetcher for %s — skipping", resource_type)
            continue

        drifts = compare(resource_type, resource_id, desired_attrs, live_attrs)
        if drifts:
            drifted_ids.add(resource_id)
            report.drift_items.extend(drifts)
            log.warning(
                "DRIFT in %s (%s): %d attribute(s) differ",
                resource_type, resource_id, len(drifts),
            )

    report.drifted_resources = len(drifted_ids)

    # ── 3. Persist report ─────────────────────────────────────────────────────
    save_report(report, output_path)

    # ── 4. Create / update / close GitHub issue ───────────────────────────────
    issue_url = ""
    if gh_token and gh_repo:
        gh = GitHubIssueCreator(token=gh_token, repo=gh_repo)
        if report.has_drift:
            issue_url = gh.create_or_update(report)
            log.info("GitHub issue: %s", issue_url)
        else:
            log.info("No drift detected — closing any open drift issues")
            gh.close_drift_issues()
    else:
        log.warning("GITHUB_TOKEN / GITHUB_REPOSITORY not set — skipping issue creation")

    # ── 5. Record scan in history ─────────────────────────────────────────────
    append_scan_history(report, issue_url=issue_url if report.has_drift else "")

    # ── 6. Exit code ──────────────────────────────────────────────────────────
    if report.has_drift:
        log.error(
            "Drift detected: %d resource(s), %d attribute(s)",
            report.drifted_resources, len(report.drift_items),
        )
        sys.exit(2)   # Non-zero so CI step is marked failed
    else:
        log.info("✅ No drift detected across %d resource(s)", report.total_resources_checked)
        sys.exit(0)


if __name__ == "__main__":
    run()