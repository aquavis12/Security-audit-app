# AWS Security Audit Application

A comprehensive AWS security audit tool built with Flask and Python. Audit multiple AWS regions from a single account with 20 security checks covering EC2, S3, IAM, RDS, and more.

## Features

- **20 Comprehensive Security Checks** across AWS services
- **Multi-Region Support** - Audit up to 3 regions per scan for optimal performance
- **Cross-Account Access** - Secure role assumption with mandatory External ID
- **Professional PDF Reports** - Detailed findings with recommendations and AWS documentation links
- **Real-time Results** - Interactive UI with severity-based prioritization
- **S3 Integration** - Automatic report storage in customer's account with presigned URLs
- **Single Bucket Architecture** - One S3 bucket per customer, organized by region and timestamp

## Security Checks (20 Total)

### Critical Severity
- EC2 Security Groups open to Internet (0.0.0.0/0)
- S3 Public Buckets (ACLs + Public Access Block)
- RDS/Aurora Backup Encryption

### High Severity
- S3 Bucket Policies with excessive permissions
- EBS Unencrypted Volumes
- RDS Unencrypted Instances
- Aurora Unencrypted Clusters
- AMI Unencrypted Images
- EC2 IMDSv2 not enforced
- Backup Vault Encryption
- ECS Encryption Issues
- API Gateway Log Encryption
- CloudFront HTTPS Enforcement

### Medium/Low Severity
- IAM Inactive Users (60+ days)
- IAM Unused Access Keys (90+ days)
- IAM Unused Roles (120+ days)
- EC2 Unused Key Pairs
- Unused KMS Keys
- Unused Secrets Manager Secrets
- Parameter Store Unused Parameters

## Prerequisites

- Python 3.11+
- AWS Account with appropriate IAM permissions
- AWS CLI configured (optional)

## Project Structure

```
aws-security-audit/
├── backend/
│   ├── app.py              # Flask REST API & frontend server
│   ├── sa.py               # Security audit logic
│   ├── requirements.txt    # Python dependencies
│   └── __init__.py
├── templates/
│   └── index.html          # Frontend HTML/CSS/JS
├── apprunner.yaml          # AWS App Runner config
├── .gitignore
└── README.md
```

## Local Development Setup

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Run Flask development server
python -m flask --app backend.app run --host 0.0.0.0 --port 8080
```

Application runs on `http://localhost:8080`

## Customer IAM Role Setup

Customers **MUST** create an IAM role named **`SecurityAuditRole`** in their AWS account:

### Trust Policy (Allow App Runner to assume this role)

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::183631310514:role/AppRunnerSecurityAuditRole"
    },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {
        "sts:ExternalId": "YOUR_UNIQUE_EXTERNAL_ID"
      }
    }
  }]
}
```

### Permissions Policy (Read-only audit + S3 for reports)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:List*",
        "s3:GetBucket*",
        "iam:List*",
        "iam:Get*",
        "rds:Describe*",
        "backup:List*",
        "backup:Describe*",
        "logs:Describe*",
        "ecs:List*",
        "ecs:Describe*",
        "apigateway:GET",
        "cloudfront:List*",
        "cloudfront:Get*",
        "kms:List*",
        "kms:Describe*",
        "secretsmanager:List*",
        "secretsmanager:Describe*",
        "ssm:Describe*",
        "ssm:GetParameter*"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:PutObject",
        "s3:GetObject",
        "s3:PutBucketVersioning",
        "s3:PutBucketEncryption",
        "s3:PutPublicAccessBlock"
      ],
      "Resource": [
        "arn:aws:s3:::aws-security-audit-*",
        "arn:aws:s3:::aws-security-audit-*/*"
      ]
    }
  ]
}
```

**Important Notes:**
- ⚠️ Role name MUST be exactly `SecurityAuditRole` (case-sensitive)
- ⚠️ External ID is mandatory for security
- ⚠️ Trust policy must include the App Runner role ARN: `arn:aws:iam::183631310514:role/AppRunnerSecurityAuditRole`

## Usage

1. Customer provides: Account ID (12 digits), Role Name (`SecurityAuditRole`), External ID
2. Select up to 3 regions and security checks
3. Click "Run Security Audit"
4. View results and download PDF report from customer's S3 bucket

## Deployment (AWS App Runner)

1. Push code to GitHub
2. Connect GitHub to App Runner
3. App Runner automatically detects `apprunner.yaml` and deploys
4. Attach IAM role: `AppRunnerSecurityAuditRole` (Instance role in Security settings)

## Architecture

- **Frontend**: HTML/CSS/JavaScript served from Flask templates
- **Backend**: Python Flask REST API
- **Runtime**: Single Python 3.11 runtime (no Node.js required)
- **Deployment**: AWS App Runner with IAM role for cross-account access
- **Authentication**: Cross-account role assumption with External ID
- **Storage**: One S3 bucket per customer (`aws-security-audit-{account_id}`)

### How It Works

1. Customer creates IAM role in their account with trust policy allowing App Runner role
2. Customer provides Account ID, Role Name (`SecurityAuditRole`), and External ID via web form
3. App Runner assumes customer's role using STS
4. Security checks run in customer's account with assumed credentials
5. PDF report created and stored in customer's S3 bucket
6. Customer downloads report via presigned S3 URL (expires in 1 hour)

## Troubleshooting

- **Access Denied**: Verify External ID matches exactly and trust policy includes App Runner role ARN
- **Invalid Region**: Use valid AWS region codes (e.g., us-east-1, eu-west-1). Max 3 regions per audit
- **S3 Bucket Failed**: Ensure role has S3 permissions for `aws-security-audit-*` buckets

---

**Powered by SUDO** | AWS Security Audit Tool
