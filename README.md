# AWS Security Audit Application

A comprehensive AWS security audit tool with a React frontend and Python backend. Audit multiple AWS regions from a single account with 19 security checks covering EC2, S3, IAM, RDS, and more.

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
- Node.js 18+
- AWS Account with appropriate IAM permissions
- AWS CLI configured (optional)

## Project Structure

```
aws-security-audit/
├── backend/
│   ├── app.py              # Flask REST API
│   ├── sa.py               # Security audit logic
│   ├── requirements.txt    # Python dependencies
│   └── __init__.py
├── frontend/
│   ├── src/
│   │   ├── App.js          # Main React component
│   │   ├── App.css         # Styles
│   │   ├── index.js        # React entry point
│   │   └── index.css       # Global styles
│   ├── public/
│   │   └── index.html
│   └── package.json
├── docs/
│   ├── AWS_Security_Audit_Architecture.png
│   ├── BUSINESS_PROPOSAL_TEMPLATE.txt
│   └── DOCKER_DEPLOYMENT.md
├── .gitignore
└── README.md
```

## Local Development Setup

### Backend Setup

```bash
# Create virtual environment
python -m venv backend/venv

# Activate virtual environment
# On Windows:
backend\venv\Scripts\activate
# On macOS/Linux:
source backend/venv/bin/activate

# Install dependencies
pip install -r backend/requirements.txt

# Run backend
python backend/app.py
```

Backend runs on `http://localhost:8080`

### Frontend Setup

```bash
# Install dependencies
cd frontend
npm install

# Build for production
npm run build

# For development (separate terminal):
npm start
```

Frontend development server runs on `http://localhost:3000`

### Production Build

```bash
# Build frontend
cd frontend
npm run build

# Backend serves built frontend automatically
python backend/app.py
```

Access application at `http://localhost:8080`

## Configuration

### AWS Credentials

The application uses AWS STS to assume roles in target accounts. Configure your AWS credentials:

```bash
aws configure
```

Or set environment variables:
```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

### IAM Role Setup (Target Account)

Create an IAM role in the account you want to audit:

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
    }
  ]
}
```

**Trust Relationship (REQUIRED):**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::YOUR_AUDIT_ACCOUNT_ID:root"
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

## Performance Notes

- **Single Region**: ~30 seconds
- **Two Regions**: ~45 seconds
- **Three Regions**: ~60 seconds
- Max 3 regions recommended for optimal performance
- Auditing 1 region at a time is fastest

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
3. Configure:
   - Runtime: Python 3.11
   - Build command: `pip install -r backend/requirements.txt`
   - Start command: `gunicorn --bind 0.0.0.0:8080 backend.app:app`
   - Port: 8080
   - CPU: 1 vCPU
   - Memory: 2 GB

See `docs/DOCKER_DEPLOYMENT.md` for Docker deployment options.

## Cost Estimation

- **AWS App Runner**: $50-200/month (depending on usage)
- **S3 Storage**: $5-10/month
- **CloudWatch Logs**: $5-10/month
- **Total**: ~$60-220/month

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

## Documentation

- `docs/AWS_Security_Audit_Architecture.png` - System architecture diagram
- `docs/BUSINESS_PROPOSAL_TEMPLATE.txt` - Business case and ROI analysis
- `docs/DOCKER_DEPLOYMENT.md` - Docker deployment guide

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
