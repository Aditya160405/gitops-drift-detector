# 🔍 DriftWatch — GitOps Config Drift Detector

> Automatically detects when someone manually changes an AWS resource in the console, compares it against your Terraform state, and raises a GitHub issue with full remediation guidance.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    GitHub Actions (Scheduled)                    │
│              Runs every 6 hours via cron: "0 */6 * * *"         │
└───────────────────────────┬─────────────────────────────────────┘
                            │
              ┌─────────────▼──────────────┐
              │   drift_detector.py         │
              │   - Reads TF state (S3)     │
              │   - Queries live AWS APIs   │
              │   - Compares attributes     │
              │   - Assigns severity        │
              └────────┬────────┬───────────┘
                       │        │
          ┌────────────▼─┐  ┌───▼──────────────┐
          │  AWS APIs     │  │  GitHub Issues   │
          │  EC2, S3, IAM │  │  Auto-create /   │
          │  RDS, ELB     │  │  update / close  │
          └───────────────┘  └──────────────────┘
                       │
          ┌────────────▼──────────────┐
          │  drift-report.json        │
          │  (uploaded as artifact)   │
          └───────────────────────────┘
                       │
          ┌────────────▼──────────────┐
          │  Ansible Playbook         │
          │  (optional remediation,   │
          │   requires manual review) │
          └───────────────────────────┘
```

---

## Project Structure

```
gitops-drift-detector/
├── .github/
│   └── workflows/
│       └── drift-detection.yml   # Scheduled GitHub Actions pipeline
├── scripts/
│   ├── drift_detector.py         # Core detection engine
│   └── requirements.txt
├── terraform/
│   └── main.tf                   # Sample infrastructure + IAM role for scanner
├── ansible/
│   └── remediate_drift.yml       # Automated remediation playbook
└── dashboard/
    └── index.html                # Live drift monitoring dashboard
```

---

## How It Works

### 1. Terraform State as Source of Truth
The detector reads your `.tfstate` file (from a local path, S3 backend, or `terraform show -json`) and extracts every resource's desired attributes.

### 2. Live AWS API Comparison
For each resource type, a dedicated fetcher queries the real AWS API:

| Resource Type | API Used | Key Attributes Checked |
|---|---|---|
| `aws_instance` | EC2 DescribeInstances | instance_type, ami, state, subnet |
| `aws_security_group` | EC2 DescribeSecurityGroups | ingress/egress rule counts |
| `aws_s3_bucket` | S3 Get* | versioning, encryption, public access block |
| `aws_iam_role` | IAM GetRole | assume_role_policy, session duration |
| `aws_db_instance` | RDS DescribeDBInstances | multi_az, publicly_accessible, encryption |
| `aws_lb` | ELBv2 DescribeLoadBalancers | scheme, type, ip_address_type |

### 3. Severity Classification

| Severity | Examples | Action |
|---|---|---|
| 🔴 Critical | S3 public access disabled, RDS encryption off | Immediate — blocks pipeline |
| 🟠 High | Security group rules changed, IAM policy modified | Urgent |
| 🟡 Medium | EC2 instance type changed, session duration modified | Review |
| 🟢 Low | Tag changes | Monitor |

### 4. GitHub Issue Lifecycle
- **Drift detected** → Issue created (or updated if one already exists)
- **Drift resolved** → Issue automatically closed on next clean scan

---

## Setup

### Prerequisites
- AWS account with appropriate permissions
- GitHub repository
- Terraform state stored in S3 (or local)

### Step 1: Create the IAM Role

```bash
cd terraform
terraform init
terraform apply -target=aws_iam_role.drift_detector
```

Copy the output `drift_detector_role_arn`.

### Step 2: Configure GitHub Secrets

| Secret | Description |
|---|---|
| `AWS_DRIFT_DETECTOR_ROLE_ARN` | ARN from Step 1 |
| `TF_STATE_S3_BUCKET` | Your Terraform state bucket |
| `TF_STATE_S3_KEY` | Path to state file in bucket |
| `SLACK_WEBHOOK_URL` | (Optional) Slack notifications |

### Step 3: Deploy infrastructure

```bash
terraform apply
```

### Step 4: Push to GitHub

The workflow triggers automatically every 6 hours. You can also run it manually from the Actions tab.

---

## Running Locally

```bash
# Install dependencies
pip install -r scripts/requirements.txt

# Configure environment
export AWS_REGION=us-east-1
export AWS_PROFILE=your-profile
export TF_STATE_S3_BUCKET=your-bucket
export TF_STATE_S3_KEY=terraform.tfstate
export GITHUB_TOKEN=ghp_...
export GITHUB_REPOSITORY=your-org/your-repo

# Run detection
python scripts/drift_detector.py

# View report
cat drift-report.json | python -m json.tool
```

---

## Extending the Detector

To add support for a new resource type:

1. Add a `_fetch_<type>` method to `AWSStateReader`
2. Register it in the `fetch()` dispatch table
3. Add severity overrides in `SEVERITY_OVERRIDES` if needed
4. Add ignored attributes in `IGNORED_ATTRIBUTES` if needed

---

## Technologies Used

- **Python 3.12** — Core detection engine
- **Terraform** — Infrastructure as Code, state backend
- **AWS SDK (boto3)** — Live state fetching (EC2, S3, IAM, RDS, ELBv2)
- **GitHub Actions** — Scheduled CI/CD pipeline with OIDC auth
- **GitHub Issues API** — Automated issue lifecycle management
- **Ansible** — Optional automated remediation playbook
- **AWS IAM OIDC** — Keyless, short-lived AWS credentials (no long-lived secrets)

---

## Dashboard

Open `dashboard/index.html` in a browser for a live drift monitoring UI featuring:
- Real-time severity breakdown donut chart
- Filterable drift items table
- Scan history timeline
- Quick remediation guide
- Interactive scan simulation

---

*Built as a DevOps internals project demonstrating Terraform state inspection, AWS Config, GitHub API automation, and scheduled GitOps pipelines.*
