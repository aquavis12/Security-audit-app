# AWS Security Audit Application

A comprehensive AWS security audit tool built with Flask and Python. Audit multiple AWS regions from a single account with **46 security checks** covering EC2, S3, IAM, RDS, DynamoDB, Lambda, and more.

## Features

### Core Capabilities
- **46 Comprehensive Security Checks** across 12 AWS service categories
- **Multi-Region Support** - Audit up to 3 regions per scan for optimal performance
- **Cross-Account Access** - Secure role assumption with mandatory External ID
- **Professional PDF Reports** - Detailed findings with recommendations and AWS documentation links
- **Real-time Results** - Interactive UI with severity-based prioritization
- **S3 Integration** - Automatic report storage in customer's account with presigned URLs
- **Single Bucket Architecture** - One S3 bucket per customer, organized by region and timestamp

### Advanced Features
- **Compliance Framework Support** - Filter checks by CIS, PCI-DSS, HIPAA, NIST, GDPR, ISO27001
- **Compliance Scoring** - Automatic calculation of compliance percentage per framework
- **Multi-Language Reports** - Generate PDF reports in English or Arabic
- **CloudFront Detection** - Identifies legitimate public S3 buckets served via CloudFront
- **Enhanced Findings** - Detailed explanations, remediation steps, and AWS documentation links
- **Smart Categorization** - Checks organized by Network, Storage, Database, Identity, Compute, etc.

## Security Checks (46 Total)

### Network Security (3 checks)
1. **EC2 Security Groups Open to Internet** `[CIS, PCI-DSS, HIPAA, NIST]`
   - Detects security groups allowing 0.0.0.0/0 access
   - Automatically excludes ALB/NLB security groups
   
2. **EC2 IMDSv2 Not Enforced** `[CIS, NIST]`
   - Identifies instances not using IMDSv2 (metadata service v2)
   
3. **EC2 Public IPs** `[CIS, NIST]`
   - EC2 instances with public IPs in private subnets

### Storage Security (6 checks)
4. **S3 Public Buckets** `[CIS, PCI-DSS, HIPAA, GDPR]`
   - Detects publicly accessible buckets with CloudFront detection
   - Differentiates between legitimate CloudFront use and direct public access
   
5. **S3 Bucket Policies - Excessive Permissions** `[CIS, PCI-DSS, HIPAA]`
   - Identifies policies with wildcard principals, actions, or resources
   
6. **S3 Versioning Disabled** `[CIS]`
   - Buckets without versioning enabled
   
7. **S3 Bucket Logging Disabled** `[CIS, PCI-DSS, HIPAA]`
   - Buckets without access logging enabled
   
8. **EBS Unencrypted Volumes** `[CIS, PCI-DSS, HIPAA, NIST]`
   - EBS volumes without encryption at rest
   
9. **EBS Unencrypted Snapshots** `[CIS, PCI-DSS, HIPAA]`
   - EBS snapshots without encryption

### Database Security (6 checks)
10. **DynamoDB Unencrypted Tables** `[CIS, PCI-DSS, HIPAA]`
    - Tables without encryption at rest enabled
    
11. **RDS Public Access** `[CIS, PCI-DSS, HIPAA]`
    - RDS instances with PubliclyAccessible=true
    
12. **RDS Unencrypted** `[CIS, PCI-DSS, HIPAA, GDPR]`
    - RDS instances without storage encryption
    
13. **RDS Multi-AZ Disabled** `[CIS, PCI-DSS, HIPAA]`
    - RDS instances without Multi-AZ for high availability
    
14. **Aurora Unencrypted** `[CIS, PCI-DSS, HIPAA, GDPR]`
    - Aurora clusters without storage encryption
    
15. **RDS/Aurora Backup Unencrypted** `[CIS, PCI-DSS, HIPAA]`
    - Database snapshots without encryption

### Identity & Access Management (6 checks)
16. **Root MFA Disabled** `[CIS, PCI-DSS, HIPAA, NIST]`
    - Root account without MFA enabled (critical security risk)
    
17. **IAM Password Policy Non-Compliant** `[CIS, PCI-DSS, HIPAA]`
    - Password policy not meeting compliance requirements (length, complexity, expiry)
    
18. **IAM Inactive Users** `[CIS, PCI-DSS, HIPAA]`
    - Users not logged in for 60+ days
    
19. **IAM Unused Access Keys** `[CIS, PCI-DSS, HIPAA]`
    - Access keys not used for 90+ days
    
20. **IAM Unused Roles** `[CIS]`
    - Roles not used for 120+ days
    
21. **IAM Users Without MFA** `[CIS, PCI-DSS, HIPAA]`
    - IAM users without multi-factor authentication

### Compute Security (4 checks)
22. **AMI Unencrypted** `[CIS, PCI-DSS, HIPAA]`
    - AMIs with unencrypted EBS snapshots
    
23. **EC2 Unused Key Pairs** `[CIS]`
    - Key pairs not attached to any running instances
    
24. **ECS Encryption Issues** `[PCI-DSS, HIPAA]`
    - ECS tasks with encryption concerns on persistent storage
    
25. **EC2 Instances Without Detailed Monitoring** `[CIS]`
    - Instances without CloudWatch detailed monitoring

### Application Security (2 checks)
26. **API Gateway Log Unencrypted** `[PCI-DSS, HIPAA]`
    - API Gateway CloudWatch logs without KMS encryption
    
27. **CloudFront HTTPS Not Enforced** `[CIS, PCI-DSS, HIPAA]`
    - CloudFront distributions not enforcing HTTPS

### Secrets & Keys Management (5 checks)
28. **Unused KMS Keys** `[CIS]`
    - Disabled or unused KMS customer master keys
    
29. **Unused Secrets** `[CIS, PCI-DSS, HIPAA]`
    - Secrets Manager secrets not accessed for 90+ days
    
30. **Secrets Without Customer-Managed KMS** `[CIS, PCI-DSS, HIPAA]`
    - Secrets using AWS-managed keys instead of customer-managed KMS (compliance requirement)
    - Note: All secrets ARE encrypted, this flags AWS-managed vs customer-managed keys
    
31. **SSM Parameters - Plaintext** `[CIS, PCI-DSS, HIPAA]`
    - SSM Parameter Store parameters using String/StringList (plaintext) instead of SecureString
    
32. **Stale SSM Parameters** `[CIS]`
    - Parameters not modified for 60+ days

### Backup & Recovery (1 check)
33. **Unencrypted Backup Vaults** `[CIS, PCI-DSS, HIPAA]`
    - AWS Backup vaults without KMS encryption

### Serverless Security (3 checks)
34. **Public Lambda Functions** `[CIS, PCI-DSS, HIPAA]`
    - Lambda functions with public access policies (Principal: "*")
    
35. **Unencrypted SNS Topics** `[PCI-DSS, HIPAA]`
    - SNS topics without KMS encryption
    
36. **Unencrypted SQS Queues** `[PCI-DSS, HIPAA]`
    - SQS queues without KMS encryption

### Monitoring & Logging (5 checks)
37. **CloudTrail Issues** `[CIS, PCI-DSS, HIPAA, NIST]`
    - CloudTrail logging disabled, not encrypted, or log validation disabled
    
38. **VPC Flow Logs Disabled** `[CIS, PCI-DSS]`
    - VPCs without flow logs enabled for network monitoring
    
39. **ELB Access Logs Disabled** `[CIS, PCI-DSS]`
    - Load balancers without access logging enabled
    
40. **CloudWatch Log Groups Unencrypted** `[PCI-DSS, HIPAA]`
    - CloudWatch log groups without KMS encryption
    
41. **Config Recorder Disabled** `[CIS, PCI-DSS]`
    - AWS Config not recording resource configurations

### Container Security (2 checks)
42. **ECR Image Scanning Disabled** `[CIS, PCI-DSS]`
    - ECR repositories without image scanning enabled
    
43. **ECS Task Definition Issues** `[PCI-DSS, HIPAA]`
    - ECS task definitions with security concerns

### Additional Compliance Checks (3 checks)
44. **GuardDuty Disabled** `[CIS, PCI-DSS, HIPAA]`
    - GuardDuty threat detection not enabled
    
45. **Security Hub Disabled** `[CIS, PCI-DSS]`
    - AWS Security Hub not enabled for centralized security findings
    
46. **Macie Disabled** `[PCI-DSS, HIPAA, GDPR]`
    - Amazon Macie not enabled for sensitive data discovery

---

**Total: 46 Comprehensive Security Checks**

**Compliance Framework Coverage:**
- **CIS AWS Foundations Benchmark**: 35 checks
- **PCI-DSS**: 32 checks  
- **HIPAA**: 28 checks
- **NIST**: 5 checks
- **GDPR**: 4 checks
- **ISO27001**: Covered through CIS/NIST alignment

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

### Basic Audit
1. Customer provides: Account ID (12 digits), Role Name (`SecurityAuditRole`), External ID
2. Select up to 3 regions and security checks
3. Click "Run Security Audit"
4. View results and download PDF report from customer's S3 bucket

### Advanced Options

#### Compliance Framework Filtering
- Select one or more frameworks: **CIS**, **PCI-DSS**, **HIPAA**, **NIST**, **GDPR**, **ISO27001**
- Checks are automatically filtered to show only relevant ones for selected frameworks
- PDF report includes compliance scoring per framework

#### Multi-Language Reports
- Choose report language: **English** or **Arabic** (العربية)
- All labels, severity levels, and findings are translated
- Arabic reports use proper Arabic fonts (Arial/DejaVu Sans)

#### API Usage
```bash
POST /api/audit
Content-Type: application/json

{
  "accountId": "123456789012",
  "roleName": "SecurityAuditRole",
  "externalId": "your-unique-external-id",
  "regions": ["us-east-1", "eu-west-1"],
  "selectedChecks": ["EC2_SG_OPEN_0_0_0_0", "S3_PUBLIC_BUCKET", ...],
  "complianceFrameworks": ["CIS", "PCI-DSS", "HIPAA"],
  "reportLanguage": "ar"
}
```

### Understanding Results

#### Severity Levels
- 🔴 **Critical** - Immediate action required (24-48 hours)
- 🟠 **High** - Fix within 1 week
- 🟡 **Medium** - Fix within 2 weeks
- 🟢 **Low** - Address during regular maintenance

#### S3 Public Bucket Detection
- **Public (CloudFront)** - Legitimate use case for website hosting
- **Public (Direct)** - Security risk requiring immediate attention
- Tool automatically detects CloudFront distributions and OAI/OAC configurations

#### Compliance Scoring
- **90%+** - ✓ Compliant (Green)
- **70-89%** - ⚠ Partial Compliance (Yellow)
- **<70%** - ✗ Non-Compliant (Red)

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

## Key Improvements & Features

### Enhanced Security Checks
- **CloudFront Detection**: Automatically identifies S3 buckets legitimately served via CloudFront
- **Compliance Mapping**: Each check mapped to relevant compliance frameworks
- **Detailed Explanations**: Every finding includes why it's flagged and how to fix it
- **AWS Documentation Links**: Direct links to official AWS security best practices

### Secrets & Encryption Clarity
- **Secrets Manager**: Flags secrets using AWS-managed keys vs customer-managed KMS keys (compliance requirement)
- **SSM Parameters**: Identifies plaintext parameters (String/StringList) vs encrypted (SecureString)
- **DynamoDB**: Checks for encryption at rest with proper formatting
- All checks include clear explanations of encryption requirements

### PDF Report Enhancements
- **Professional Design**: Blue/white color scheme with clear severity indicators
- **Compliance Scores**: Automatic calculation per framework with pass/fail status
- **Multi-Language**: Full Arabic translation support with proper font embedding
- **Detailed Findings**: Resource-level details with remediation steps
- **Executive Summary**: Risk assessment and priority recommendations

### Arabic Language Support
- Full translation of all UI elements and PDF content
- Proper Arabic font support (Arial/DejaVu Sans/Liberation Sans)
- Automatic font detection and registration
- Severity levels, compliance status, and all labels in Arabic
- Note: Text displays left-to-right due to ReportLab RTL limitations

## API Endpoints

### `GET /api/checks`
Returns categorized list of all 46 security checks with compliance mappings.

**Response:**
```json
{
  "checks": {
    "Network Security": [
      {
        "id": "EC2_SG_OPEN_0_0_0_0",
        "name": "Open Security Groups",
        "severity": "Critical",
        "description": "Security groups allowing 0.0.0.0/0 access",
        "compliance": ["PCI-DSS", "HIPAA", "CIS", "NIST"]
      }
    ]
  }
}
```

### `POST /api/audit`
Runs security audit with specified parameters.

**Request Body:**
```json
{
  "accountId": "123456789012",
  "roleName": "SecurityAuditRole",
  "externalId": "unique-external-id",
  "regions": ["us-east-1", "eu-west-1"],
  "selectedChecks": ["EC2_SG_OPEN_0_0_0_0", "S3_PUBLIC_BUCKET"],
  "complianceFrameworks": ["CIS", "PCI-DSS"],
  "reportLanguage": "en"
}
```

**Response:**
```json
{
  "success": true,
  "summary": {
    "total": 28,
    "critical": 19,
    "high": 9,
    "medium": 0,
    "low": 0,
    "regions_audited": 2
  },
  "report": {
    "s3_bucket": "aws-security-audit-123456789012",
    "s3_key": "us-east-1/aws_audit_20251120T073446Z.pdf",
    "presigned_url": "https://...",
    "expires_in": 3600
  }
}
```

## Troubleshooting

### Common Issues

**Access Denied**
- Verify External ID matches exactly
- Ensure trust policy includes App Runner role ARN: `arn:aws:iam::183631310514:role/AppRunnerSecurityAuditRole`
- Check role name is exactly `SecurityAuditRole` (case-sensitive)

**Invalid Region**
- Use valid AWS region codes (e.g., us-east-1, eu-west-1)
- Maximum 3 regions per audit for optimal performance

**S3 Bucket Creation Failed**
- Ensure role has S3 permissions for `aws-security-audit-*` buckets
- Check S3 CreateBucket, PutObject, and PutBucketEncryption permissions

**Arabic Text Shows as Boxes**
- Ensure system has Arial (Windows), DejaVu Sans (Linux), or Arial Unicode (macOS)
- Open PDF in Adobe Acrobat Reader for best font support
- Check logs for "Registered Arabic font from:" message

**Compliance Scores Not Showing**
- Ensure `complianceFrameworks` array is provided in request
- At least one framework must be selected: CIS, PCI-DSS, HIPAA, NIST, GDPR, or ISO27001

### Debug Mode
Check application logs for detailed error messages:
```bash
# View App Runner logs
aws logs tail /aws/apprunner/SecurityAuditApp --follow
```

## Documentation

- **SECURITY_CHECKS_IMPROVEMENTS.md** - Detailed explanation of all check improvements
- **QUICK_REFERENCE_CHECKS.md** - Quick reference for understanding check logic
- **ARABIC_PDF_FINAL_FIXES.md** - Arabic language support implementation details
- **COMPLIANCE_FRAMEWORK_ROADMAP.md** - Multi-tenant architecture design

## Contributing

This is a proprietary tool developed by SUDO Consultants. For feature requests or bug reports, contact the development team.

## License

Proprietary - All rights reserved by SUDO Consultants

---

**Powered by SUDO** | AWS Security Audit Tool v2.0

**Latest Updates:**
- ✅ 46 comprehensive security checks (expanded from 20)
- ✅ Compliance framework support (CIS, PCI-DSS, HIPAA, NIST, GDPR, ISO27001)
- ✅ Multi-language PDF reports (English & Arabic)
- ✅ CloudFront detection for S3 public buckets
- ✅ Enhanced findings with detailed explanations
- ✅ Compliance scoring and framework filtering
