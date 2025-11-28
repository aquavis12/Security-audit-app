# Authentication & Authorization Module

Prowler-inspired cross-account IAM role assumption with External ID security.

## Overview

This module handles secure cross-account access to customer AWS accounts using:
- **IAM Role Assumption** - STS AssumeRole with temporary credentials
- **External ID** - Mandatory security parameter to prevent confused deputy problem
- **Request Validation** - Comprehensive input validation for all audit parameters
- **Credential Management** - Secure credential handling and expiration tracking

## Components

### 1. IAMRoleManager (`iam_role_manager.py`)

Manages cross-account role assumption with security best practices.

**Key Features:**
- Validates account ID, role name, and External ID format
- Assumes role with mandatory External ID
- Tracks credential expiration
- Comprehensive error handling with specific error codes
- Audit logging for security compliance

**Usage:**

```python
from backend.auth.iam_role_manager import IAMRoleManager

manager = IAMRoleManager()

credentials = manager.assume_role(
    account_id='123456789012',
    role_name='SecurityAuditRole',
    external_id='your-unique-external-id',
    region='us-east-1'
)

# credentials = {
#     'aws_access_key_id': '...',
#     'aws_secret_access_key': '...',
#     'aws_session_token': '...',
#     'expiration': '2024-11-27T...'
# }
```

### 2. AuditRequestValidator (`validators.py`)

Validates all audit request parameters before processing.

**Validation Rules:**

| Parameter | Rules | Example |
|-----------|-------|---------|
| Account ID | 12 digits only | `123456789012` |
| Role Name | 1-64 chars, alphanumeric + `+=,.@-` | `SecurityAuditRole` |
| External ID | 2-1224 chars | `your-unique-external-id` |
| Regions | 1-3 valid AWS regions | `['us-east-1', 'eu-west-1']` |
| Checks | 1-50 check IDs | `['EC2_SG_OPEN_0_0_0_0', ...]` |
| Frameworks | Valid compliance frameworks | `['CIS', 'PCI-DSS', 'HIPAA']` |

**Usage:**

```python
from backend.auth.validators import AuditRequestValidator

validator = AuditRequestValidator()

# Validate complete request
is_valid, error = validator.validate_audit_request({
    'accountId': '123456789012',
    'roleName': 'SecurityAuditRole',
    'externalId': 'unique-external-id',
    'regions': ['us-east-1'],
    'selectedChecks': ['EC2_SG_OPEN_0_0_0_0'],
    'complianceFrameworks': ['CIS', 'PCI-DSS']
})

if not is_valid:
    print(f"Validation error: {error}")

# Or validate individual fields
is_valid, error = validator.validate_account_id('123456789012')
is_valid, error = validator.validate_external_id('unique-external-id')
```

### 3. AuditCredentials (`iam_role_manager.py`)

Wrapper for temporary credentials with expiration tracking.

**Usage:**

```python
from backend.auth.iam_role_manager import AuditCredentials

creds = AuditCredentials(credentials_dict)

# Check if expired
if creds.is_expired():
    print("Credentials have expired, need to re-assume role")

# Get as dict for boto3
boto3_creds = creds.to_dict()
```

## Security Best Practices

### 1. External ID (Confused Deputy Prevention)

The External ID is a security token that prevents the "confused deputy problem":

```
Customer Account (123456789012)
├── Role: SecurityAuditRole
├── Trust Policy: Allows App Runner role to assume
└── Condition: ExternalId = "unique-external-id"

App Runner Account (183631310514)
├── Role: AppRunnerSecurityAuditRole
└── Assumes: SecurityAuditRole with ExternalId
```

**Why it matters:**
- Without External ID, any AWS principal could assume the role
- External ID adds an additional security layer
- Must be kept secret and unique per customer

### 2. Credential Lifecycle

```
1. Customer provides: Account ID, Role Name, External ID
2. App Runner assumes role → Gets temporary credentials
3. Credentials valid for 1 hour (default)
4. Audit runs with assumed credentials
5. Credentials automatically expire
6. No long-term credentials stored
```

### 3. Validation Strategy

All inputs are validated before use:

```python
# Request validation flow
1. Check required fields present
2. Validate account ID format (12 digits)
3. Validate role name format (1-64 chars)
4. Validate External ID (2-1224 chars)
5. Validate regions (1-3, must be valid AWS regions)
6. Validate checks (1-50 check IDs)
7. Validate frameworks (if provided)
```

## Error Handling

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `AccessDenied` | Trust policy doesn't allow assumption | Check trust policy includes App Runner role ARN |
| `ValidationError` | Invalid parameters | Check account ID, role name, External ID format |
| `NoSuchEntity` | Role doesn't exist | Verify role name is exactly `SecurityAuditRole` |
| `InvalidParameterValue` | External ID mismatch | Ensure External ID matches trust policy |

### Error Response Format

```json
{
  "error": "Invalid account ID. Must be 12 digits"
}
```

## Integration with Flask

The auth module is integrated into `app.py`:

```python
from backend.auth.iam_role_manager import IAMRoleManager
from backend.auth.validators import AuditRequestValidator

iam_role_manager = IAMRoleManager()
validator = AuditRequestValidator()

@app.route('/api/audit', methods=['POST'])
def run_audit():
    data = request.json
    
    # Validate request
    is_valid, error_msg = validator.validate_audit_request(data)
    if not is_valid:
        return jsonify({'error': error_msg}), 400
    
    # Assume role
    try:
        credentials = iam_role_manager.assume_role(
            account_id=data['accountId'],
            role_name=data['roleName'],
            external_id=data['externalId'],
            region=data['regions'][0]
        )
    except Exception as e:
        return jsonify({'error': f'Failed to assume role: {str(e)}'}), 403
    
    # Continue with audit...
```

## Customer Setup

### 1. Create IAM Role

Customer must create `SecurityAuditRole` in their account:

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

### 2. Attach Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "ec2:Describe*",
      "s3:List*",
      "iam:List*",
      "rds:Describe*",
      "backup:List*"
    ],
    "Resource": "*"
  }]
}
```

### 3. Provide to App

Customer provides:
- Account ID: `123456789012`
- Role Name: `SecurityAuditRole`
- External ID: `your-unique-external-id`

## Testing

```bash
# Test role assumption
python -c "
from backend.auth.iam_role_manager import IAMRoleManager
manager = IAMRoleManager()
creds = manager.assume_role(
    account_id='123456789012',
    role_name='SecurityAuditRole',
    external_id='test-external-id',
    region='us-east-1'
)
print('✅ Role assumption successful')
"

# Test validation
python -c "
from backend.auth.validators import AuditRequestValidator
validator = AuditRequestValidator()
is_valid, error = validator.validate_account_id('123456789012')
print(f'Valid: {is_valid}, Error: {error}')
"
```

## Logging

All authentication operations are logged:

```
2024-11-27 10:30:45 - root - INFO - Attempting to assume role: arn:aws:iam::123456789012:role/SecurityAuditRole
2024-11-27 10:30:46 - root - INFO - ✅ Successfully assumed role: arn:aws:iam::123456789012:role/SecurityAuditRole
2024-11-27 10:30:46 - root - DEBUG - Session expires at: 2024-11-27T11:30:46+00:00
```

## References

- [AWS STS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [External ID](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html)
- [Confused Deputy Problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html)
- [Prowler Authentication](https://docs.prowler.cloud/en/latest/getting-started/authentication/)
