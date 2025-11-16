# AWS Security Audit Application

A comprehensive AWS security audit tool built with Flask and Python. Audit multiple AWS regions from a single account with 19 security checks covering EC2, S3, IAM, RDS, and more.

## Features

- **19 Comprehensive Security Checks** across AWS services
- **Multi-Region Support** - Audit up to 3 regions per scan for optimal performance
- **Cross-Account Access** - Secure role assumption with mandatory External ID
- **Professional PDF Reports** - Detailed findings with recommendations and AWS documentation links
- **Real-time Results** - Interactive UI with severity-based prioritization
- **S3 Integration** - Automatic report storage with presigned URLs

## Security Checks

### Critical Severity
- EC2 Security Groups open to Internet (0.0.0.0/0)
- S3 Public Buckets
- RDS/Aurora Backup Encryption

### High Severity
- S3 Bucket Policies with excessive permissions
- EBS Unencrypted Volumes
- RDS Unencrypted Instances
- Aurora Unencrypted Clusters
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

### Setup

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

The Flask server serves both the REST API and the HTML frontend from `templates/index.html`.

## Configuration

### AWS Credentials

#### Local Development
Configure your AWS credentials for the account that will assume the audit role:

```bash
aws configure
```

Or set environment variables:
```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

#### AWS App Runner Deployment
App Runner requires an IAM role (`AppRunnerSecurityAuditRole`) with permission to assume customer roles. This role is already created and attached to the service.

### IAM Role Setup (Customer/Target Account)

Customers need to create an IAM role in their AWS account with the following configuration:

**Step 1: Create IAM Role**
- Role name: `SecurityAuditRole` (or any name)
- Role type: Cross-account role

**Step 2: Trust Policy (Allow App Runner to assume this role)**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
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
    }
  ]
}
```

**Step 3: Permissions Policy (Read-only audit + S3 for reports)**

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

**Step 4: Provide to Application**
- Account ID (12 digits)
- Role Name (e.g., SecurityAuditRole)
- External ID (unique string for security)

## Usage

1. **Open Application**
   - Navigate to `http://localhost:8080`

2. **Configure Audit**
   - **Regions**: Select up to 3 regions (dropdown)
   - **Account ID**: 12-digit AWS account ID
   - **IAM Role Name**: Name of the role to assume
   - **External ID**: Unique external ID from trust policy

3. **Select Security Checks**
   - Choose specific checks or select all
   - Uncheck to skip certain checks

4. **Run Audit**
   - Click "Run Security Audit"
   - Wait for results (30-60 seconds for 3 regions)

5. **View Results**
   - Review findings by severity
   - Download PDF report from S3

## API Endpoints

### Health Check
```bash
GET /health
```

### Get Available Checks
```bash
GET /api/checks
```

### Run Audit
```bash
POST /api/audit
Content-Type: application/json

{
  "accountId": "123456789012",
  "roleName": "SecurityAuditRole",
  "externalId": "unique-external-id",
  "regions": ["us-east-1", "eu-west-1"],
  "selectedChecks": ["EC2_SG_OPEN_0_0_0_0", "S3_PUBLIC_BUCKET"],
  "s3Bucket": "optional-bucket-name"
}
```

Response includes:
- Summary (total, critical, high, medium, low findings)
- Detailed findings by region
- S3 bucket location and presigned URL for PDF


## Security Best Practices

1. **External ID**: Always use a unique, random External ID
   ```bash
   # Generate External ID
   python -c "import uuid; print(uuid.uuid4())"
   ```

2. **Least Privilege**: Grant only read-only permissions to audit role

3. **Encryption**: All data encrypted in transit (HTTPS) and at rest (S3)

4. **Presigned URLs**: PDF reports expire in 1 hour

5. **Audit Trail**: All API calls logged to CloudWatch

## Deployment

### AWS App Runner (Recommended)

1. Push code to GitHub
2. Connect GitHub to App Runner
3. App Runner automatically detects `apprunner.yaml` and deploys with:
   - Runtime: Python 3.11
   - Build: Installs dependencies from `backend/requirements.txt`
   - Start: Runs gunicorn on port 8080
   - CPU: 1 vCPU
   - Memory: 2 GB

4. **Attach IAM Role to App Runner** (Required):
   - Role: `AppRunnerSecurityAuditRole`
   - ARN: `arn:aws:iam::183631310514:role/AppRunnerSecurityAuditRole`
   - Permission: Allows assuming `SecurityAuditRole` in customer accounts
   - Go to App Runner → Security → Instance role → Select the role

The `apprunner.yaml` file handles all configuration automatically.


## Troubleshooting

### "Failed to assume role"
- Verify External ID matches exactly (case-sensitive)
- Check trust policy in target account
- Ensure IAM role has required permissions

### "Invalid region"
- Use valid AWS region codes (e.g., us-east-1, eu-west-1)
- Max 3 regions per audit

### "S3 bucket creation failed"
- Ensure AWS credentials have S3 permissions
- Bucket name must be globally unique

### Slow audit performance
- Reduce number of regions (max 3)
- Run 1 region at a time for fastest results
- Check AWS API rate limits

## Architecture

- **Frontend**: HTML/CSS/JavaScript served from Flask templates
- **Backend**: Python Flask REST API
- **Runtime**: Single Python 3.11 runtime
- **Deployment**: AWS App Runner with IAM role for cross-account access
- **Authentication**: Cross-account role assumption with External ID
- **Storage**: PDF reports stored in customer's S3 bucket (not in app account)

### How It Works

1. **Customer Setup**: Customer creates IAM role in their account with trust policy allowing your App Runner role
2. **User Input**: Customer provides Account ID, Role Name, and External ID via web form
3. **Role Assumption**: App Runner assumes customer's role using STS
4. **Audit Execution**: Security checks run in customer's account with assumed credentials
5. **Report Storage**: PDF report created and stored in customer's S3 bucket
6. **Download**: Customer downloads report via presigned S3 URL (expires in 1 hour)

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review AWS documentation links in PDF reports
3. Verify IAM permissions and External ID configuration

## License

This project is provided as-is for AWS security auditing purposes.

## Contributing

Contributions welcome. Please ensure:
- Code follows existing style
- All 19 security checks remain functional
- Documentation is updated
- Tests pass before submitting

---

**Powered by SUDO** | AWS Security Audit Tool
