###############################################################################
# GitOps Drift Detector — Fixed AWS Infrastructure
###############################################################################

terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket  = "aditya-drift-tfstate"
    key     = "terraform.tfstate"
    region  = "ap-south-1"
    encrypt = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      ManagedBy   = "Terraform"
      Project     = "GitOpsDriftDemo"
      Environment = var.environment
    }
  }
}

###############################################################################
# VARIABLES
###############################################################################

variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "ap-south-1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "staging"

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production."
  }
}

variable "ec2_instance_type" {
  description = "EC2 instance type for the demo app server"
  type        = string
  default     = "t3.micro"
}

variable "github_org" {
  description = "Your GitHub username or org name"
  type        = string
  default     = "your-github-username"   # <-- change this
}

variable "github_repo" {
  description = "Your GitHub repo name"
  type        = string
  default     = "gitops-drift-detector"  # <-- change if different
}

variable "ssh_public_key" {
  description = "Public SSH key contents for EC2 access"
  type        = string
}

###############################################################################
# NETWORKING
###############################################################################

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "drift-demo-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"

  tags = { Name = "drift-demo-public-subnet" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "drift-demo-igw" }
}

# Route table — without this the public subnet has no internet access
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "drift-demo-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

###############################################################################
# SECURITY GROUP — monitored for drift
###############################################################################

resource "aws_security_group" "app" {
  name        = "drift-demo-app-sg"
  description = "Security group for the demo application server"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH - restrict to your IP in production"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "DriftWatch dashboard"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "drift-demo-app-sg" }
}

###############################################################################
# EC2 INSTANCE — monitored for drift
###############################################################################

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_caller_identity" "current" {}

resource "aws_key_pair" "deployer" {
  key_name   = "drift-demo-key"
  public_key = var.ssh_public_key
}

resource "aws_instance" "app" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.ec2_instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name
  monitoring             = true
  key_name = aws_key_pair.deployer.key_name

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = 30
    encrypted             = true
    delete_on_termination = true
  }

  user_data = base64encode(<<-EOT
    #!/bin/bash
    yum update -y
    yum install -y python3 python3-pip git
    pip3 install boto3 requests
  EOT
  )

  tags = { Name = "drift-demo-app-server" }

  lifecycle {
    ignore_changes = [ami, user_data]
  }
}

###############################################################################
# S3 BUCKET — monitored for public access, encryption, versioning
###############################################################################

resource "aws_s3_bucket" "assets" {
  bucket = "drift-demo-assets-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "drift-demo-assets" }
}

resource "aws_s3_bucket_versioning" "assets" {
  bucket = aws_s3_bucket.assets.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

###############################################################################
# IAM ROLE for EC2 app — monitored for drift
###############################################################################

resource "aws_iam_role" "app" {
  name = "drift-demo-app-role"
  path = "/app/"

  # FIX: was "sts" — must be "sts:AssumeRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })

  max_session_duration = 3600
  tags                 = { Name = "drift-demo-app-role" }
}

# FIX: was "arn:aws:iam::aws/AmazonSSMManagedInstanceCore" (wrong slash)
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "drift_scan" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_instance_profile" "app" {
  name = "drift-demo-app-profile"
  role = aws_iam_role.app.name
}

###############################################################################
# IAM ROLE for Drift Detector (GitHub Actions OIDC)
###############################################################################

resource "aws_iam_role" "drift_detector" {
  name = "GitOpsDriftDetector"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      # FIX: was bare "sts" — must be "sts:AssumeRoleWithWebIdentity"
      Action = "sts:AssumeRoleWithWebIdentity"
      Effect = "Allow"
      Principal = {
        # FIX: was missing "oidc-provider/" in the ARN
        Federated = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:oidc-provider/token.actions.githubusercontent.com"
      }
      Condition = {
        StringEquals = {
          # FIX: key was missing ":aud"
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          # FIX: key was missing ":sub"; also pinned to YOUR repo now
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.github_repo}:*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy" "drift_detector" {
  name = "DriftDetectorPolicy"
  role = aws_iam_role.drift_detector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EC2ReadOnly"
        Effect = "Allow"
        # FIX: was bare "ec2" strings — AWS requires "service:Action" format
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeRouteTables",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeVolumes",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Sid    = "S3ReadOnly"
        Effect = "Allow"
        # FIX: was bare "s3" strings
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketVersioning",
          "s3:GetBucketEncryption",
          "s3:GetBucketPublicAccessBlock"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMReadOnly"
        Effect = "Allow"
        # FIX: was bare "iam" strings
        Action = [
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies"
        ]
        Resource = "*"
      },
      {
        Sid    = "RDSReadOnly"
        Effect = "Allow"
        # FIX: was bare "rds" string
        Action   = ["rds:DescribeDBInstances"]
        Resource = "*"
      },
      {
        Sid    = "ELBReadOnly"
        Effect = "Allow"
        # FIX: was bare "elasticloadbalancing" string
        Action   = ["elasticloadbalancing:DescribeLoadBalancers"]
        Resource = "*"
      },
      {
        Sid    = "TFStateRead"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        # FIX: was "kaushal-drift-tfstate" (friend's bucket)
        # FIX: was missing /* for object-level access
        Resource = [
          "arn:aws:s3:::aditya-drift-tfstate",
          "arn:aws:s3:::aditya-drift-tfstate/*"
        ]
      }
    ]
  })
}

###############################################################################
# RDS (optional — uncomment to demo RDS drift detection)
###############################################################################

# resource "aws_db_instance" "main" {
#   identifier          = "drift-demo-db"
#   engine              = "postgres"
#   engine_version      = "15.4"
#   instance_class      = "db.t3.micro"
#   allocated_storage   = 20
#   storage_encrypted   = true
#   deletion_protection = true
#   multi_az            = false
#   publicly_accessible = false
#   skip_final_snapshot = true
#   tags                = { Name = "drift-demo-db" }
# }

###############################################################################
# OUTPUTS
###############################################################################

output "drift_detector_role_arn" {
  description = "Paste this as AWS_DRIFT_DETECTOR_ROLE_ARN in GitHub Actions secrets"
  value       = aws_iam_role.drift_detector.arn
}

output "app_instance_id" {
  description = "EC2 instance ID to watch for drift"
  value       = aws_instance.app.id
}

output "app_security_group_id" {
  description = "Security group ID to watch for drift"
  value       = aws_security_group.app.id
}

output "assets_bucket_name" {
  description = "S3 bucket name to watch for drift"
  value       = aws_s3_bucket.assets.id
}

output "app_public_ip" {
  description = "Public IP of the DriftWatch app server (Ansible/Jenkins reads this)"
  value       = aws_instance.app.public_ip
}
