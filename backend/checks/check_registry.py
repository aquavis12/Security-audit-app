"""
Check Registry - Prowler-inspired check management
Centralized registry of all security checks with metadata
"""

from dataclasses import dataclass
from typing import List, Dict, Callable

@dataclass
class CheckMetadata:
    """Metadata for each security check"""
    check_id: str
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low
    service: str  # ec2, s3, iam, rds, etc.
    category: str  # Network, Storage, Identity, etc.
    compliance: List[str]  # CIS, PCI-DSS, HIPAA, etc.
    risk: str
    remediation: str
    documentation: str

# Check Registry - Maps check_id to metadata and function
CHECK_REGISTRY: Dict[str, CheckMetadata] = {
    'EC2_SG_OPEN_0_0_0_0': CheckMetadata(
        check_id='EC2_SG_OPEN_0_0_0_0',
        title='Security Groups Open to Internet',
        description='Security groups allowing 0.0.0.0/0 access (excludes ALB/NLB)',
        severity='Critical',
        service='ec2',
        category='Network Security',
        compliance=['CIS', 'PCI-DSS', 'HIPAA', 'NIST'],
        risk='Unrestricted network access increases attack surface',
        remediation='Restrict security group rules to specific IP ranges',
        documentation='https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html'
    ),
    'S3_PUBLIC_BUCKET': CheckMetadata(
        check_id='S3_PUBLIC_BUCKET',
        title='Public S3 Buckets',
        description='S3 buckets with public access (excludes CloudFront)',
        severity='Critical',
        service='s3',
        category='Storage Security',
        compliance=['CIS', 'PCI-DSS', 'HIPAA', 'GDPR'],
        risk='Public buckets may expose sensitive data',
        remediation='Enable S3 Block Public Access and review bucket policies',
        documentation='https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html'
    ),
    'IAM_USER_INACTIVE': CheckMetadata(
        check_id='IAM_USER_INACTIVE',
        title='Inactive IAM Users',
        description='Users not logged in for 60+ days',
        severity='Critical',
        service='iam',
        category='Identity & Access',
        compliance=['CIS', 'PCI-DSS', 'HIPAA'],
        risk='Inactive accounts increase security risk',
        remediation='Disable or remove inactive IAM users',
        documentation='https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html'
    ),
    'RDS_PUBLIC_ACCESS': CheckMetadata(
        check_id='RDS_PUBLIC_ACCESS',
        title='Public RDS Instances',
        description='RDS instances publicly accessible',
        severity='Critical',
        service='rds',
        category='Database Security',
        compliance=['CIS', 'PCI-DSS', 'HIPAA'],
        risk='Public databases are vulnerable to attacks',
        remediation='Set PubliclyAccessible to false',
        documentation='https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_CommonTasks.Connect.html'
    ),
    'ROOT_MFA_DISABLED': CheckMetadata(
        check_id='ROOT_MFA_DISABLED',
        title='Root MFA Disabled',
        description='Root account without MFA enabled',
        severity='Critical',
        service='iam',
        category='Identity & Access',
        compliance=['CIS', 'PCI-DSS', 'HIPAA', 'NIST'],
        risk='Root account compromise has catastrophic impact',
        remediation='Enable MFA for root account immediately',
        documentation='https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html'
    ),
}

def get_check_metadata(check_id: str) -> CheckMetadata:
    """Get metadata for a specific check"""
    return CHECK_REGISTRY.get(check_id)

def get_checks_by_service(service: str) -> List[CheckMetadata]:
    """Get all checks for a specific service"""
    return [meta for meta in CHECK_REGISTRY.values() if meta.service == service]

def get_checks_by_category(category: str) -> List[CheckMetadata]:
    """Get all checks for a specific category"""
    return [meta for meta in CHECK_REGISTRY.values() if meta.category == category]

def get_checks_by_compliance(framework: str) -> List[str]:
    """Get check IDs for a compliance framework"""
    return [
        meta.check_id 
        for meta in CHECK_REGISTRY.values() 
        if framework in meta.compliance
    ]
