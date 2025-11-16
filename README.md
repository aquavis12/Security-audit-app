# AWS Security Audit Application

Comprehensive AWS security audit tool with 20 security checks across EC2, S3, IAM, RDS, and more.

## Features

- **20 Security Checks** - EC2, S3, IAM, RDS, Aurora, EBS, AMI, KMS, Secrets Manager, Parameter Store
- **Multi-Region Support** - Audit up to 3 regions per scan
- **Cross-Account Access** - Secure role assumption with External ID
- **PDF Reports** - Stored in customer's S3 bucket with presigned URLs
- **Single Python Runtime** - Flask backend with HTML/CSS/JS frontend

## Prerequisites

- Python 3.11+
- AWS Account with IAM permissions

## Quick Start

```bash
# Install dependencies
pip install -r backend/requirements.txt

# Run locally
python -m flask --app backend.app run --host 0.0.0.0 --port 8080
```

## Customer Setup

Customers must create an IAM role named **`SecurityAuditRole`** in their AWS account:

**Trust Policy:**
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
        "sts:ExternalId": "CUSTOMER_UNIQUE_EXTERNAL_ID"
      }
    }
  }]
}
```

**Permissions:** Read-only access to EC2, S3, IAM, RDS, etc. + S3 write for reports

## Usage

1. Customer provides: Account ID, Role Name (`SecurityAuditRole`), External ID
2. Select regions (max 3) and security checks
3. Run audit
4. Download PDF report from customer's S3 bucket

## Deployment (AWS App Runner)

1. Push to GitHub
2. Connect to App Runner
3. Attach IAM role: `AppRunnerSecurityAuditRole`
4. Deploy automatically via `apprunner.yaml`

## Security Checks (20 Total)

**Critical:** EC2 Security Groups Open, S3 Public Buckets, RDS/Aurora Backup Unencrypted
**High:** S3 Policies, EBS/RDS/Aurora/AMI Unencrypted, IMDSv2, Backup Vaults, ECS, API Gateway, CloudFront
**Low:** IAM Inactive Users/Keys/Roles, Unused Key Pairs/KMS Keys/Secrets/Parameters

## Architecture

- **Frontend:** HTML/CSS/JS (Flask templates)
- **Backend:** Python Flask REST API
- **Authentication:** Cross-account role assumption with External ID
- **Storage:** One S3 bucket per customer (`aws-security-audit-{account_id}`)
- **Reports:** Organized by region and timestamp

## API Endpoints

- `GET /health` - Health check
- `GET /api/checks` - List available checks
- `POST /api/audit` - Run security audit

## Troubleshooting

- **Access Denied:** Verify trust policy includes App Runner role ARN
- **Invalid Region:** Use valid AWS region codes (us-east-1, eu-west-1, etc.)
- **S3 Bucket Failed:** Ensure role has S3 permissions

## License

Provided as-is for AWS security auditing.

---

**Powered by SUDO** | AWS Security Audit Tool
