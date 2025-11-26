"""
AWS Security Audit Tool - Comprehensive Security Assessment
============================================================

This tool performs 19 comprehensive security checks across your AWS environment:

1. EC2 Security Groups - Open to Internet (0.0.0.0/0) - Excludes ALB/NLB
2. S3 Public Buckets - Publicly accessible buckets
3. S3 Bucket Policies - Excessive permissions with wildcards
4. IAM Inactive Users - Users not logged in for 60+ days
5. IAM Unused Access Keys - Keys not used for 90+ days
6. IAM Unused Roles - Roles not used for 120+ days
7. EBS Unencrypted Volumes - Volumes without encryption
8. RDS Unencrypted Instances - Database instances without encryption
9. Aurora Unencrypted Clusters - Aurora clusters without encryption
10. RDS/Aurora Backup Encryption - Unencrypted database backups
11. EC2 IMDSv2 - Instances not using IMDSv2
12. EC2 Unused Key Pairs - Key pairs not attached to any instance
13. Backup Vault Encryption - AWS Backup vaults without KMS encryption
14. ECS Encryption Issues - ECS tasks with encryption concerns
15. API Gateway Log Encryption - CloudWatch logs without KMS encryption
16. CloudFront HTTPS - Distributions not enforcing HTTPS
17. Unused KMS Keys - Disabled or unused KMS keys
18. Unused Secrets - Secrets Manager secrets not accessed for 90+ days
19. Parameter Store - Unused SSM parameters not modified for 60+ days

Each check includes:
- Detailed findings with resource information
- Severity rating (Critical, High, Medium, Low)
- Actionable recommendations
- AWS documentation links
- Remediation commands where applicable

Report Features:
- Professional blue/white color scheme
- Executive summary with compliance status
- Findings breakdown by severity
- Detailed resource information
- AWS best practices documentation URLs
"""

import boto3
from datetime import datetime, timedelta, timezone
import json
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
from botocore.exceptions import ClientError
import random

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Helper function for timezone-aware datetime
def utcnow():
    """Get current UTC time (timezone-aware)"""
    return datetime.now(timezone.utc)

# Severity levels for prioritization
# 3 = Critical, 2 = High, 1 = Medium, 0 = Low
SEVERITY_MAP = {
    'EC2_SG_OPEN_0_0_0_0': 3,
    'S3_PUBLIC_BUCKET': 3,
    'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS': 2,
    'S3_VERSIONING_DISABLED': 0,
    'IAM_USER_INACTIVE': 3,
    'IAM_ACCESS_KEY_UNUSED': 2,
    'IAM_ROLE_UNUSED': 0,
    'EBS_UNENCRYPTED': 2,
    'EBS_SNAPSHOT_UNENCRYPTED': 2,
    'DYNAMODB_UNENCRYPTED': 2,
    'RDS_UNENCRYPTED': 2,
    'RDS_PUBLIC_ACCESS': 3,
    'AURORA_UNENCRYPTED': 2,
    'RDS_AURORA_BACKUP_UNENCRYPTED': 3,
    'ROOT_MFA_DISABLED': 3,
    'BACKUP_VAULT_UNENCRYPTED': 2,
    'EC2_NO_IMDSV2': 2,
    'EC2_UNUSED_KEY_PAIR': 1,
    'AMI_UNENCRYPTED': 2,
    'ECS_ENCRYPTION_ISSUE': 2,
    'API_GW_LOG_UNENCRYPTED': 2,
    'CLOUDFRONT_ENCRYPTION_ISSUE': 2,
    'UNUSED_KMS_KEYS': 0,
    'UNUSED_SECRETS': 1,
    'SECRETS_UNENCRYPTED': 0,
    'SSM_PARAMETERS_UNENCRYPTED': 0,
    'PARAMETER_STORE_ISSUE': 1,
    'VPC_NO_FLOW_LOGS': 1,
    'LAMBDA_PUBLIC_ACCESS': 3,
    'ELB_NO_LOGGING': 1,
    'SNS_UNENCRYPTED': 2,
    'SQS_UNENCRYPTED': 2,
    'CLOUDTRAIL_ISSUES': 3,
    'EC2_PUBLIC_IP': 2,
    'GUARDDUTY_DISABLED': 2,
    'SECURITYHUB_DISABLED': 1,
    'INSPECTOR_DISABLED': 1,
    'VPC_LOGS_UNENCRYPTED': 1,
    'ECR_TAG_MUTABLE': 1
}

# Compliance Framework Mapping - which checks map to which frameworks
COMPLIANCE_MAPPING = {
    'EC2_SG_OPEN_0_0_0_0': ['CIS', 'PCI-DSS', 'HIPAA', 'NIST'],
    'S3_PUBLIC_BUCKET': ['CIS', 'PCI-DSS', 'HIPAA', 'GDPR'],
    'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS': ['CIS', 'PCI-DSS', 'HIPAA'],
    'EBS_UNENCRYPTED': ['CIS', 'PCI-DSS', 'HIPAA', 'NIST'],
    'EBS_SNAPSHOT_UNENCRYPTED': ['CIS', 'PCI-DSS', 'HIPAA'],
    'DYNAMODB_UNENCRYPTED': ['CIS', 'PCI-DSS', 'HIPAA'],
    'RDS_PUBLIC_ACCESS': ['CIS', 'PCI-DSS', 'HIPAA'],
    'RDS_UNENCRYPTED': ['CIS', 'PCI-DSS', 'HIPAA', 'GDPR'],
    'AURORA_UNENCRYPTED': ['CIS', 'PCI-DSS', 'HIPAA', 'GDPR'],
    'RDS_AURORA_BACKUP_UNENCRYPTED': ['CIS', 'PCI-DSS', 'HIPAA'],
    'ROOT_MFA_DISABLED': ['CIS', 'PCI-DSS', 'HIPAA', 'NIST'],
    'IAM_USER_INACTIVE': ['CIS', 'PCI-DSS', 'HIPAA'],
    'IAM_ACCESS_KEY_UNUSED': ['CIS', 'PCI-DSS', 'HIPAA'],
    'IAM_ROLE_UNUSED': ['CIS'],
    'AMI_UNENCRYPTED': ['CIS', 'PCI-DSS', 'HIPAA'],
    'EC2_UNUSED_KEY_PAIR': ['CIS'],
    'ECS_ENCRYPTION_ISSUE': ['PCI-DSS', 'HIPAA'],
    'API_GW_LOG_UNENCRYPTED': ['PCI-DSS', 'HIPAA'],
    'CLOUDFRONT_ENCRYPTION_ISSUE': ['CIS', 'PCI-DSS', 'HIPAA'],
    'UNUSED_KMS_KEYS': ['CIS'],
    'UNUSED_SECRETS': ['CIS', 'PCI-DSS', 'HIPAA'],
    'SECRETS_UNENCRYPTED': ['CIS', 'PCI-DSS', 'HIPAA'],
    'SSM_PARAMETERS_UNENCRYPTED': ['CIS', 'PCI-DSS', 'HIPAA'],
    'PARAMETER_STORE_ISSUE': ['CIS'],
    'BACKUP_VAULT_UNENCRYPTED': ['CIS', 'PCI-DSS', 'HIPAA'],
    'LAMBDA_PUBLIC_ACCESS': ['CIS', 'PCI-DSS', 'HIPAA'],
    'SNS_UNENCRYPTED': ['PCI-DSS', 'HIPAA'],
    'SQS_UNENCRYPTED': ['PCI-DSS', 'HIPAA'],
    'CLOUDTRAIL_ISSUES': ['CIS', 'PCI-DSS', 'HIPAA', 'NIST'],
    'VPC_NO_FLOW_LOGS': ['CIS', 'PCI-DSS'],
    'ELB_NO_LOGGING': ['CIS', 'PCI-DSS'],
    'EC2_NO_IMDSV2': ['CIS', 'NIST'],
    'EC2_PUBLIC_IP': ['CIS', 'NIST'],
    'GUARDDUTY_DISABLED': ['CIS', 'PCI-DSS', 'HIPAA', 'NIST'],
    'SECURITYHUB_DISABLED': ['CIS', 'NIST'],
    'INSPECTOR_DISABLED': ['CIS', 'NIST'],
    'VPC_LOGS_UNENCRYPTED': ['CIS', 'NIST', 'PCI-DSS'],
    'ECR_TAG_MUTABLE': ['CIS', 'PCI-DSS']
}

# AWS Security Best Practices References
AWS_SECURITY_REFERENCES = {
    'EC2_SG_OPEN_0_0_0_0': 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html',
    'S3_PUBLIC_BUCKET': 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html',
    'IAM_USER_INACTIVE': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    'IAM_ACCESS_KEY_UNUSED': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
    'EBS_UNENCRYPTED': 'https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html',
    'RDS_UNENCRYPTED': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
    'EC2_NO_IMDSV2': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
    'GENERAL': 'https://aws.amazon.com/security/security-resources/'
}

class AWSecurityAudit:
    def __init__(self, region_name, credentials=None):
        self.region = region_name
        try:
            # Use provided credentials (from assumed role) or default credentials
            client_kwargs = {'region_name': region_name}
            if credentials:
                client_kwargs.update({
                    'aws_access_key_id': credentials['aws_access_key_id'],
                    'aws_secret_access_key': credentials['aws_secret_access_key'],
                    'aws_session_token': credentials['aws_session_token']
                })
            
            self.ec2 = boto3.client('ec2', **client_kwargs)
            self.iam = boto3.client('iam', **{k: v for k, v in client_kwargs.items() if k != 'region_name'})
            self.s3 = boto3.client('s3', **{k: v for k, v in client_kwargs.items() if k != 'region_name'})
            self.rds = boto3.client('rds', **client_kwargs)
            self.backup = boto3.client('backup', **client_kwargs)
            self.logs = boto3.client('logs', **client_kwargs)
            self.ecr = boto3.client('ecr', **client_kwargs)
            self.ecs = boto3.client('ecs', **client_kwargs)
            self.apigw = boto3.client('apigateway', **client_kwargs)
            self.kms = boto3.client('kms', **client_kwargs)
            self.secrets = boto3.client('secretsmanager', **client_kwargs)
            self.ssm = boto3.client('ssm', **client_kwargs)
            self.cloudfront = boto3.client('cloudfront', **{k: v for k, v in client_kwargs.items() if k != 'region_name'})
            logger.info(f"✅ AWS clients initialized for region: {region_name}")
        except Exception as e:
            logger.error(f"❌ Failed to initialize AWS clients: {str(e)}")
            raise

    def check_ec2_security_groups(self):
        """Check for security groups with 0.0.0.0/0 access - excluding ALB/NLB"""
        try:
            logger.info("Checking EC2 security groups...")
            sgs = self.ec2.describe_security_groups()['SecurityGroups']
            
            # Get all load balancers (ALB/NLB) and their security groups
            elb_client = boto3.client('elbv2', region_name=self.region)
            lb_security_groups = set()
            
            try:
                load_balancers = elb_client.describe_load_balancers()['LoadBalancers']
                for lb in load_balancers:
                    # Add all security groups attached to load balancers
                    lb_security_groups.update(lb.get('SecurityGroups', []))
                    logger.debug(f"Load balancer {lb.get('LoadBalancerName', 'Unknown')} uses SGs: {lb.get('SecurityGroups', [])}")
            except Exception as e:
                logger.debug(f"Could not fetch load balancers: {str(e)}")
            
            logger.info(f"Found {len(lb_security_groups)} security groups attached to ALB/NLB (will be excluded)")
            
            open_sgs = []
            for sg in sgs:
                sg_id = sg['GroupId']
                
                # Skip if this SG is attached to a load balancer
                if sg_id in lb_security_groups:
                    logger.debug(f"Skipping {sg_id} - attached to ALB/NLB")
                    continue
                
                for perm in sg['IpPermissions']:
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            from_port = perm.get('FromPort', 'All')
                            to_port = perm.get('ToPort', 'All')
                            protocol = perm.get('IpProtocol', 'All')
                            
                            # Get VPC info
                            vpc_id = sg.get('VpcId', 'N/A')
                            
                            open_sgs.append({
                                'GroupId': sg_id,
                                'GroupName': sg.get('GroupName', 'N/A'),
                                'Port': f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                                'Protocol': protocol,
                                'VpcId': vpc_id,
                                'Description': sg.get('Description', 'No description')[:50]
                            })
                            break
            
            logger.info(f"Found {len(open_sgs)} open security groups (excluding ALB/NLB)")
            return open_sgs
        except Exception as e:
            logger.error(f"Error checking security groups: {str(e)}")
            return []

    def check_s3_public_buckets(self):
        """Check for publicly accessible S3 buckets - checks ACLs, Public Access Block, and CloudFront usage"""
        try:
            logger.info("Checking S3 public buckets...")
            buckets = self.s3.list_buckets().get('Buckets', [])
            
            # Get all CloudFront distributions to check if buckets are served via CloudFront
            cloudfront_buckets = set()
            try:
                cf_distributions = self.cloudfront.list_distributions().get('DistributionList', {}).get('Items', [])
                for dist in cf_distributions:
                    origins = dist.get('Origins', {}).get('Items', [])
                    for origin in origins:
                        domain = origin.get('DomainName', '')
                        # Extract bucket name from S3 domain (e.g., bucket-name.s3.amazonaws.com)
                        if '.s3.' in domain or '.s3-' in domain:
                            bucket_from_domain = domain.split('.s3')[0]
                            cloudfront_buckets.add(bucket_from_domain)
                logger.info(f"Found {len(cloudfront_buckets)} buckets served via CloudFront")
            except Exception as e:
                logger.debug(f"Could not fetch CloudFront distributions: {str(e)}")
            
            public_buckets = []
            for bucket in buckets:
                try:
                    bucket_name = bucket['Name']
                    creation_date = bucket.get('CreationDate', 'Unknown')
                    if creation_date != 'Unknown':
                        creation_date = creation_date.strftime('%Y-%m-%d')
                    
                    is_public = False
                    public_reason = []
                    has_cloudfront = bucket_name in cloudfront_buckets
                    
                    # Check 1: Public ACLs
                    try:
                        acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                        for grant in acl.get('Grants', []):
                            grantee = grant.get('Grantee', {})
                            if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                                is_public = True
                                public_reason.append(f"Public ACL ({grant.get('Permission', 'Unknown')})")
                    except Exception:
                        pass
                    
                    # Check 2: Public Access Block settings
                    try:
                        pab = self.s3.get_public_access_block(Bucket=bucket_name)
                        config = pab.get('PublicAccessBlockConfiguration', {})
                        
                        if not config.get('BlockPublicAcls', False):
                            is_public = True
                            public_reason.append("BlockPublicAcls disabled")
                        if not config.get('IgnorePublicAcls', False):
                            public_reason.append("IgnorePublicAcls disabled")
                        if not config.get('BlockPublicPolicy', False):
                            is_public = True
                            public_reason.append("BlockPublicPolicy disabled")
                        if not config.get('RestrictPublicBuckets', False):
                            is_public = True
                            public_reason.append("RestrictPublicBuckets disabled")
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                            is_public = True
                            public_reason.append("No Public Access Block")
                    except Exception:
                        pass
                    
                    # Check 3: Bucket policy for CloudFront OAI/OAC
                    cloudfront_policy = False
                    try:
                        policy_str = self.s3.get_bucket_policy(Bucket=bucket_name)['Policy']
                        policy = json.loads(policy_str)
                        for stmt in policy.get('Statement', []):
                            principal = stmt.get('Principal', {})
                            # Check for CloudFront Origin Access Identity or Origin Access Control
                            if isinstance(principal, dict):
                                if 'Service' in principal and 'cloudfront.amazonaws.com' in str(principal['Service']):
                                    cloudfront_policy = True
                                    break
                                if 'AWS' in principal and 'cloudfront' in str(principal['AWS']).lower():
                                    cloudfront_policy = True
                                    break
                    except:
                        pass
                    
                    if is_public:
                        # Skip buckets that are served via CloudFront (legitimate use case)
                        if has_cloudfront or cloudfront_policy:
                            logger.debug(f"Skipping {bucket_name} - served via CloudFront")
                            continue
                        
                        # Only report truly public buckets (not behind CloudFront)
                        public_buckets.append({
                            'BucketName': bucket_name,
                            'Created': creation_date,
                            'Access': 'Public'
                        })
                        
                except Exception as e:
                    logger.debug(f"Could not check bucket {bucket['Name']}: {str(e)}")
                    continue
            logger.info(f"Found {len(public_buckets)} public buckets")
            return public_buckets
        except Exception as e:
            logger.error(f"Error checking S3 buckets: {str(e)}")
            return []
    
    def check_s3_bucket_policies_excessive_permissions(self):
        """Check for S3 buckets with overly permissive policies - with full policy details"""
        try:
            logger.info("Checking S3 bucket policies...")
            buckets = self.s3.list_buckets().get('Buckets', [])
            risky_buckets = []
            for bucket in buckets:
                try:
                    policy_str = self.s3.get_bucket_policy(Bucket=bucket['Name'])['Policy']
                    policy = json.loads(policy_str)
                    
                    # Get bucket creation date
                    creation_date = bucket.get('CreationDate', 'Unknown')
                    if creation_date != 'Unknown':
                        creation_date = creation_date.strftime('%Y-%m-%d')
                    
                    for stmt in policy.get('Statement', []):
                        if stmt.get('Effect') == 'Allow':
                            principal = stmt.get('Principal')
                            action = stmt.get('Action')
                            resource = stmt.get('Resource')
                            
                            risk_reason = []
                            if principal == "*" or (isinstance(principal, dict) and principal.get('AWS') == "*"):
                                risk_reason.append("Public Principal (*)")
                            if action == "*" or (isinstance(action, list) and "*" in action):
                                risk_reason.append("All Actions (*)")
                            if resource == "*" or (isinstance(resource, list) and "*" in resource):
                                risk_reason.append("All Resources (*)")
                            
                            if risk_reason:
                                risky_buckets.append({
                                    'BucketName': bucket['Name'],
                                    'Created': creation_date,
                                    'Risk': ', '.join(risk_reason),
                                    'Policy': json.dumps(stmt, indent=2)[:100]
                                })
                                break
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                        continue
                    else:
                        logger.debug(f"Error checking bucket {bucket['Name']}: {str(e)}")
                        continue
                except Exception as e:
                    logger.debug(f"Error checking bucket {bucket['Name']}: {str(e)}")
                    continue
            logger.info(f"Found {len(risky_buckets)} buckets with excessive permissions")
            return risky_buckets
        except Exception as e:
            logger.error(f"Error checking S3 bucket policies: {str(e)}")
            return []

    def check_iam_users_inactive(self, days=60):
        """Check for inactive IAM users with days inactive"""
        try:
            logger.info("Checking IAM inactive users...")
            cutoff = utcnow() - timedelta(days=days)
            inactive_users = []
            users = self.iam.list_users().get('Users', [])
            for user in users:
                last_used = user.get('PasswordLastUsed')
                if not last_used:
                    days_inactive = (utcnow() - user['CreateDate']).days
                    inactive_users.append({
                        'UserName': user['UserName'],
                        'DaysInactive': days_inactive,
                        'Status': 'Never logged in'
                    })
                elif last_used < cutoff:
                    days_inactive = (utcnow() - last_used).days
                    inactive_users.append({
                        'UserName': user['UserName'],
                        'DaysInactive': days_inactive,
                        'Status': f'Last used {days_inactive} days ago'
                    })
            logger.info(f"Found {len(inactive_users)} inactive users")
            return inactive_users
        except Exception as e:
            logger.error(f"Error checking IAM users: {str(e)}")
            return []

    def check_iam_access_keys_unused(self, days=90):
        """Check for unused IAM access keys with age"""
        try:
            logger.info("Checking IAM access keys...")
            cutoff = utcnow() - timedelta(days=days)
            unused_keys = []
            users = self.iam.list_users().get('Users', [])
            for user in users:
                keys = self.iam.list_access_keys(UserName=user['UserName']).get('AccessKeyMetadata', [])
                for key in keys:
                    try:
                        last_used_resp = self.iam.get_access_key_last_used(AccessKeyId=key['AccessKeyId'])
                        last_used = last_used_resp.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                        key_age = (utcnow() - key['CreateDate']).days
                        
                        if not last_used:
                            unused_keys.append({
                                'UserName': user['UserName'],
                                'AccessKeyId': key['AccessKeyId'][-8:],
                                'Age': f'{key_age} days old',
                                'Status': 'Never used'
                            })
                        elif last_used < cutoff:
                            days_unused = (utcnow() - last_used).days
                            unused_keys.append({
                                'UserName': user['UserName'],
                                'AccessKeyId': key['AccessKeyId'][-8:],
                                'Age': f'{key_age} days old',
                                'Status': f'Unused for {days_unused} days'
                            })
                    except Exception:
                        continue
            logger.info(f"Found {len(unused_keys)} unused access keys")
            return unused_keys
        except Exception as e:
            logger.error(f"Error checking access keys: {str(e)}")
            return []

    def check_ebs_encryption(self):
        """Check for unencrypted EBS volumes with size"""
        try:
            logger.info("Checking EBS encryption...")
            volumes = self.ec2.describe_volumes().get('Volumes', [])
            unencrypted = []
            for v in volumes:
                if not v.get('Encrypted', False):
                    unencrypted.append({
                        'VolumeId': v['VolumeId'],
                        'Size': f"{v.get('Size', 0)} GB",
                        'State': v.get('State', 'unknown'),
                        'Type': v.get('VolumeType', 'unknown')
                    })
            logger.info(f"Found {len(unencrypted)} unencrypted volumes")
            return unencrypted
        except Exception as e:
            logger.error(f"Error checking EBS volumes: {str(e)}")
            return []
    
    def check_ebs_snapshot_encryption(self):
        """Check for unencrypted EBS snapshots"""
        try:
            logger.info("Checking EBS snapshot encryption...")
            snapshots = self.ec2.describe_snapshots(OwnerIds=['self']).get('Snapshots', [])
            unencrypted = []
            
            for snapshot in snapshots:
                if not snapshot.get('Encrypted', False):
                    unencrypted.append({
                        'SnapshotId': snapshot['SnapshotId'],
                        'VolumeId': snapshot.get('VolumeId', 'N/A'),
                        'Size': f"{snapshot.get('VolumeSize', 0)} GB",
                        'StartTime': snapshot.get('StartTime', 'Unknown').strftime('%Y-%m-%d') if snapshot.get('StartTime') != 'Unknown' else 'Unknown',
                        'State': snapshot.get('State', 'unknown')
                    })
            
            logger.info(f"Found {len(unencrypted)} unencrypted EBS snapshots")
            return unencrypted
        except Exception as e:
            logger.error(f"Error checking EBS snapshots: {str(e)}")
            return []
    
    def check_dynamodb_encryption(self):
        """Check for DynamoDB tables without encryption at rest"""
        try:
            logger.info("Checking DynamoDB encryption...")
            dynamodb = boto3.client('dynamodb', region_name=self.region)
            tables = dynamodb.list_tables().get('TableNames', [])
            unencrypted = []
            
            for table_name in tables:
                try:
                    table_desc = dynamodb.describe_table(TableName=table_name)
                    table = table_desc['Table']
                    
                    # Check SSE (Server-Side Encryption) status
                    sse_desc = table.get('SSEDescription', {})
                    sse_status = sse_desc.get('Status', 'DISABLED')
                    
                    if sse_status != 'ENABLED':
                        unencrypted.append({
                            'TableName': table_name,
                            'TableStatus': table.get('TableStatus', 'unknown'),
                            'ItemCount': table.get('ItemCount', 0),
                            'TableSizeBytes': f"{table.get('TableSizeBytes', 0) / 1024 / 1024:.2f} MB"
                        })
                except Exception as e:
                    logger.debug(f"Could not check table {table_name}: {str(e)}")
                    continue
            
            logger.info(f"Found {len(unencrypted)} unencrypted DynamoDB tables")
            return unencrypted
        except Exception as e:
            logger.error(f"Error checking DynamoDB encryption: {str(e)}")
            return []

    def check_rds_encryption(self):
        """Check for unencrypted RDS instances with details"""
        try:
            logger.info("Checking RDS encryption...")
            instances = self.rds.describe_db_instances().get('DBInstances', [])
            unencrypted = []
            for db in instances:
                if not db.get('StorageEncrypted', False):
                    unencrypted.append({
                        'DBInstanceIdentifier': db['DBInstanceIdentifier'],
                        'Engine': db.get('Engine', 'unknown'),
                        'Size': f"{db.get('AllocatedStorage', 0)} GB",
                        'Status': db.get('DBInstanceStatus', 'unknown')
                    })
            logger.info(f"Found {len(unencrypted)} unencrypted RDS instances")
            return unencrypted
        except Exception as e:
            logger.error(f"Error checking RDS instances: {str(e)}")
            return []

    def check_aurora_encryption(self):
        """Check for unencrypted Aurora clusters with details"""
        try:
            logger.info("Checking Aurora encryption...")
            clusters = self.rds.describe_db_clusters().get('DBClusters', [])
            unencrypted = []
            for c in clusters:
                if not c.get('StorageEncrypted', False):
                    unencrypted.append({
                        'ClusterIdentifier': c['DBClusterIdentifier'],
                        'Engine': c.get('Engine', 'unknown'),
                        'Status': c.get('Status', 'unknown'),
                        'Members': len(c.get('DBClusterMembers', []))
                    })
            logger.info(f"Found {len(unencrypted)} unencrypted Aurora clusters")
            return unencrypted
        except Exception as e:
            logger.error(f"Error checking Aurora clusters: {str(e)}")
            return []

    def check_iam_roles_unused(self, days=120):
        """Check for unused IAM roles with detailed information"""
        try:
            logger.info("Checking IAM unused roles...")
            cutoff = utcnow() - timedelta(days=days)
            roles = self.iam.list_roles().get('Roles', [])
            unused_roles = []
            
            for role in roles:
                role_name = role['RoleName']
                last_used_info = role.get('RoleLastUsed', {})
                last_used = last_used_info.get('LastUsedDate')
                create_date = role.get('CreateDate')
                
                # Calculate days since creation
                days_old = (utcnow() - create_date).days if create_date else 0
                
                # Check if role is unused
                if not last_used:
                    unused_roles.append({
                        'RoleName': role_name,
                        'Status': 'Never used',
                        'DaysOld': days_old,
                        'Path': role.get('Path', '/'),
                        'Description': role.get('Description', 'No description')[:50]
                    })
                elif last_used < cutoff:
                    days_unused = (utcnow() - last_used).days
                    unused_roles.append({
                        'RoleName': role_name,
                        'Status': f'Unused for {days_unused} days',
                        'DaysOld': days_old,
                        'Path': role.get('Path', '/'),
                        'Description': role.get('Description', 'No description')[:50]
                    })
            
            logger.info(f"Found {len(unused_roles)} unused roles out of {len(roles)} total")
            return unused_roles
        except Exception as e:
            logger.error(f"Error checking IAM roles: {str(e)}")
            return []
    
    def check_all_iam_roles(self):
        """Get all IAM roles with their details for comprehensive audit"""
        try:
            logger.info("Scanning all IAM roles...")
            roles = self.iam.list_roles().get('Roles', [])
            all_roles = []
            
            for role in roles:
                role_name = role['RoleName']
                last_used_info = role.get('RoleLastUsed', {})
                last_used = last_used_info.get('LastUsedDate')
                create_date = role.get('CreateDate')
                
                # Get attached policies
                try:
                    attached_policies = self.iam.list_attached_role_policies(RoleName=role_name)
                    policy_count = len(attached_policies.get('AttachedPolicies', []))
                except:
                    policy_count = 0
                
                # Calculate age
                days_old = (utcnow() - create_date).days if create_date else 0
                
                # Determine status
                if not last_used:
                    status = 'Never used'
                    days_since_use = days_old
                else:
                    days_since_use = (utcnow() - last_used).days
                    status = f'Last used {days_since_use} days ago'
                
                all_roles.append({
                    'RoleName': role_name,
                    'Status': status,
                    'DaysSinceUse': days_since_use,
                    'DaysOld': days_old,
                    'Policies': policy_count,
                    'Path': role.get('Path', '/'),
                    'MaxSessionDuration': role.get('MaxSessionDuration', 3600) // 3600,  # Convert to hours
                    'Description': role.get('Description', 'No description')[:50]
                })
            
            logger.info(f"Found {len(all_roles)} total IAM roles")
            return all_roles
        except Exception as e:
            logger.error(f"Error scanning all IAM roles: {str(e)}")
            return []

    def check_backup_vaults_encryption(self):
        """Check for unencrypted backup vaults with details"""
        try:
            logger.info("Checking Backup vaults...")
            vaults = self.backup.list_backup_vaults().get('BackupVaultList', [])
            unencrypted = []
            for v in vaults:
                if not v.get('EncryptionKeyArn'):
                    unencrypted.append({
                        'VaultName': v['BackupVaultName'],
                        'VaultArn': v.get('BackupVaultArn', 'N/A')
                    })
            logger.info(f"Found {len(unencrypted)} unencrypted backup vaults")
            return unencrypted
        except Exception as e:
            logger.error(f"Error checking backup vaults: {str(e)}")
            return []

    def check_ec2_imdsv2(self):
        """Check for EC2 instances not using IMDSv2"""
        try:
            logger.info("Checking EC2 IMDSv2...")
            instances_no_imds = []
            reservations = self.ec2.describe_instances().get('Reservations', [])
            for res in reservations:
                for inst in res.get('Instances', []):
                    if inst.get('State', {}).get('Name') == 'running':
                        try:
                            meta_opts = self.ec2.describe_instance_metadata_options(InstanceId=inst['InstanceId'])
                            if meta_opts['InstanceMetadataOptions'].get('HttpTokens') != 'required':
                                instances_no_imds.append(inst['InstanceId'])
                        except Exception:
                            continue
            logger.info(f"Found {len(instances_no_imds)} instances without IMDSv2")
            return instances_no_imds
        except Exception as e:
            logger.error(f"Error checking IMDSv2: {str(e)}")
            return []

    def check_ami_encryption(self):
        """Check for unencrypted AMIs"""
        try:
            logger.info("Checking AMI encryption...")
            # Get AMIs owned by the account
            images = self.ec2.describe_images(Owners=['self']).get('Images', [])
            unencrypted_amis = []
            
            for img in images:
                # Check if any block device mapping has unencrypted snapshots
                is_encrypted = True
                unencrypted_volumes = []
                
                for bdm in img.get('BlockDeviceMappings', []):
                    if 'Ebs' in bdm:
                        ebs = bdm['Ebs']
                        if not ebs.get('Encrypted', False):
                            is_encrypted = False
                            unencrypted_volumes.append(bdm.get('DeviceName', 'unknown'))
                
                if not is_encrypted:
                    unencrypted_amis.append({
                        'ImageId': img['ImageId'],
                        'Name': img.get('Name', 'N/A'),
                        'CreationDate': img.get('CreationDate', 'N/A')[:10],
                        'State': img.get('State', 'unknown'),
                        'UnencryptedVolumes': ', '.join(unencrypted_volumes)
                    })
            
            logger.info(f"Found {len(unencrypted_amis)} unencrypted AMIs")
            return unencrypted_amis
        except Exception as e:
            logger.error(f"Error checking AMI encryption: {str(e)}")
            return []

    def check_unused_key_pairs(self):
        """Check for unused EC2 key pairs with details"""
        try:
            logger.info("Checking unused key pairs...")
            key_pairs = self.ec2.describe_key_pairs().get('KeyPairs', [])
            reservations = self.ec2.describe_instances().get('Reservations', [])
            used_key_names = set()
            for res in reservations:
                for inst in res.get('Instances', []):
                    if 'KeyName' in inst:
                        used_key_names.add(inst['KeyName'])
            
            unused_keys = []
            for kp in key_pairs:
                if kp['KeyName'] not in used_key_names:
                    unused_keys.append({
                        'KeyName': kp['KeyName'],
                        'KeyPairId': kp.get('KeyPairId', 'N/A'),
                        'Fingerprint': kp.get('KeyFingerprint', 'N/A')[:20] + '...'
                    })
            logger.info(f"Found {len(unused_keys)} unused key pairs")
            return unused_keys
        except Exception as e:
            logger.error(f"Error checking key pairs: {str(e)}")
            return []

    def check_ecs_encryption_issues(self):
        clusters = self.ecs.list_clusters().get('clusterArns', [])
        issues = []
        for cluster_arn in clusters:
            task_arns = self.ecs.list_tasks(cluster=cluster_arn).get('taskArns', [])
            for task_arn in task_arns:
                task = self.ecs.describe_tasks(cluster=cluster_arn, tasks=[task_arn]).get('tasks', [])[0]
                for container in task.get('containers', []):
                    for mount in container.get('mountPoints', []):
                        # Possible manual review needed for encryption on persistent storage
                        issues.append(cluster_arn)
                        break
        return list(set(issues))

    def check_api_gateway_log_encryption(self):
        log_groups = self.logs.describe_log_groups()['logGroups']
        api_log_groups = [lg for lg in log_groups if 'API-Gateway-Execution-Logs' in lg['logGroupName']]
        unencrypted_logs = [lg['logGroupName'] for lg in api_log_groups if 'kmsKeyId' not in lg]
        return unencrypted_logs

    def check_cloudfront_encryption(self):
        dists = self.cloudfront.list_distributions().get('DistributionList', {}).get('Items', [])
        issues = []
        for d in dists:
            default_behavior = d.get('DefaultCacheBehavior', {})
            behaviors = d.get('CacheBehaviors', {}).get('Items', [])
            all_behaviors = [default_behavior] + behaviors
            for cache in all_behaviors:
                if cache.get('ViewerProtocolPolicy', '') not in ['https-only', 'redirect-to-https']:
                    issues.append(d['Id'])
        return list(set(issues))

    def check_rds_aurora_backups_encrypted(self):
        snapshots = self.rds.describe_db_snapshots()['DBSnapshots']
        unencrypted = [snap['DBSnapshotIdentifier'] for snap in snapshots if not snap.get('Encrypted', False)]
        cluster_snaps = self.rds.describe_db_cluster_snapshots()['DBClusterSnapshots']
        unencrypted += [snap['DBClusterSnapshotIdentifier'] for snap in cluster_snaps if not snap.get('Encrypted', False)]
        return unencrypted

    def check_unused_kms_keys(self, days=90):
        """Check for unused or disabled KMS keys"""
        try:
            logger.info("Checking KMS keys...")
            keys = self.kms.list_keys().get('Keys', [])
            unused = []
            for key in keys:
                key_id = key['KeyId']
                try:
                    key_metadata = self.kms.describe_key(KeyId=key_id)['KeyMetadata']
                    if not key_metadata.get('Enabled', False) or key_metadata.get('KeyState') in ['PendingDeletion', 'Disabled']:
                        unused.append(key_id)
                except Exception:
                    continue
            logger.info(f"Found {len(unused)} unused KMS keys")
            return unused
        except Exception as e:
            logger.error(f"Error checking KMS keys: {str(e)}")
            return []

    def check_unused_secrets(self, days=90):
        """Check for unused secrets in Secrets Manager"""
        try:
            logger.info("Checking Secrets Manager...")
            cutoff = utcnow() - timedelta(days=days)
            secrets = self.secrets.list_secrets().get('SecretList', [])
            unused = []
            for secret in secrets:
                last_accessed = secret.get('LastAccessedDate')
                last_rotated = secret.get('LastChangedDate')
                if (not last_accessed or last_accessed < cutoff) and \
                   (not last_rotated or last_rotated < cutoff):
                    unused.append(secret['Name'])
            logger.info(f"Found {len(unused)} unused secrets")
            return unused
        except Exception as e:
            logger.error(f"Error checking Secrets Manager: {str(e)}")
            return []
    
    def check_secrets_encryption(self):
        """Check for Secrets Manager secrets without customer-managed KMS keys (compliance requirement)"""
        try:
            logger.info("Checking Secrets Manager encryption...")
            secrets = self.secrets.list_secrets().get('SecretList', [])
            without_custom_kms = []
            
            for secret in secrets:
                secret_name = secret.get('Name', 'Unknown')
                # Check if secret uses customer-managed KMS key
                kms_key_id = secret.get('KmsKeyId')
                
                # Flag if using AWS-managed key (for compliance frameworks like PCI-DSS/HIPAA)
                # Note: All secrets are encrypted, but compliance requires customer-managed keys
                if not kms_key_id or kms_key_id == 'alias/aws/secretsmanager':
                    created_date = secret.get('CreatedDate')
                    if created_date and created_date != 'Unknown':
                        try:
                            created_date = created_date.strftime('%Y-%m-%d')
                        except:
                            created_date = 'Unknown'
                    else:
                        created_date = 'Unknown'
                    
                    encryption_type = 'AWS-Managed Key' if kms_key_id == 'alias/aws/secretsmanager' else 'Default Encryption'
                    
                    without_custom_kms.append({
                        'SecretName': secret_name,
                        'EncryptionType': encryption_type,
                        'CreatedDate': created_date,
                        'Recommendation': 'Use customer-managed KMS key for compliance'
                    })
            
            logger.info(f"Found {len(without_custom_kms)} secrets without customer-managed KMS keys")
            return without_custom_kms
        except Exception as e:
            logger.error(f"Error checking Secrets Manager encryption: {str(e)}")
            return []
    
    def check_ssm_parameters_encryption(self):
        """Check for SSM Parameter Store parameters not using SecureString (unencrypted)"""
        try:
            logger.info("Checking SSM Parameter Store encryption...")
            paginator = self.ssm.get_paginator('describe_parameters')
            unencrypted = []
            
            for page in paginator.paginate():
                for param in page.get('Parameters', []):
                    param_name = param.get('Name', 'Unknown')
                    param_type = param.get('Type', 'String')
                    
                    # SecureString is encrypted with KMS, String/StringList are plaintext
                    if param_type != 'SecureString':
                        last_modified = param.get('LastModifiedDate')
                        if last_modified and last_modified != 'Unknown':
                            try:
                                last_modified = last_modified.strftime('%Y-%m-%d')
                            except:
                                last_modified = 'Unknown'
                        else:
                            last_modified = 'Unknown'
                        
                        # Get parameter tier for context
                        tier = param.get('Tier', 'Standard')
                        
                        unencrypted.append({
                            'ParameterName': param_name,
                            'Type': param_type,
                            'Tier': tier,
                            'LastModified': last_modified,
                            'Recommendation': 'Change to SecureString type for encryption'
                        })
            
            logger.info(f"Found {len(unencrypted)} plaintext SSM parameters (not SecureString)")
            return unencrypted
        except Exception as e:
            logger.error(f"Error checking SSM Parameter Store encryption: {str(e)}")
            return []

    def check_vpc_flow_logs(self):
        """Check for VPCs without flow logs enabled"""
        try:
            logger.info("Checking VPC flow logs...")
            vpcs = self.ec2.describe_vpcs().get('Vpcs', [])
            flow_logs = self.ec2.describe_flow_logs().get('FlowLogs', [])
            
            vpcs_with_logs = set([fl['ResourceId'] for fl in flow_logs])
            vpcs_without_logs = []
            
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                if vpc_id not in vpcs_with_logs:
                    vpcs_without_logs.append({
                        'VpcId': vpc_id,
                        'IsDefault': vpc.get('IsDefault', False),
                        'CidrBlock': vpc.get('CidrBlock', 'N/A')
                    })
            
            logger.info(f"Found {len(vpcs_without_logs)} VPCs without flow logs")
            return vpcs_without_logs
        except Exception as e:
            logger.error(f"Error checking VPC flow logs: {str(e)}")
            return []
    
    def check_lambda_public_access(self):
        """Check for Lambda functions with public access"""
        try:
            logger.info("Checking Lambda public access...")
            lambda_client = boto3.client('lambda', region_name=self.region)
            functions = lambda_client.list_functions().get('Functions', [])
            public_functions = []
            
            for func in functions:
                try:
                    policy = lambda_client.get_policy(FunctionName=func['FunctionName'])
                    policy_doc = json.loads(policy['Policy'])
                    
                    for stmt in policy_doc.get('Statement', []):
                        principal = stmt.get('Principal', {})
                        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                            public_functions.append({
                                'FunctionName': func['FunctionName'],
                                'Runtime': func.get('Runtime', 'N/A'),
                                'LastModified': func.get('LastModified', 'N/A')[:10]
                            })
                            break
                except:
                    continue
            
            logger.info(f"Found {len(public_functions)} Lambda functions with public access")
            return public_functions
        except Exception as e:
            logger.error(f"Error checking Lambda functions: {str(e)}")
            return []
    
    def check_elb_logging(self):
        """Check for ELBs without access logging enabled"""
        try:
            logger.info("Checking ELB access logging...")
            elb_client = boto3.client('elbv2', region_name=self.region)
            load_balancers = elb_client.describe_load_balancers().get('LoadBalancers', [])
            elbs_without_logging = []
            
            for lb in load_balancers:
                lb_arn = lb['LoadBalancerArn']
                attrs = elb_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
                
                logging_enabled = False
                for attr in attrs.get('Attributes', []):
                    if attr['Key'] == 'access_logs.s3.enabled' and attr['Value'] == 'true':
                        logging_enabled = True
                        break
                
                if not logging_enabled:
                    elbs_without_logging.append({
                        'LoadBalancerName': lb['LoadBalancerName'],
                        'Type': lb.get('Type', 'N/A'),
                        'Scheme': lb.get('Scheme', 'N/A')
                    })
            
            logger.info(f"Found {len(elbs_without_logging)} ELBs without access logging")
            return elbs_without_logging
        except Exception as e:
            logger.error(f"Error checking ELB logging: {str(e)}")
            return []
    
    def check_sns_topic_encryption(self):
        """Check for SNS topics without encryption"""
        try:
            logger.info("Checking SNS topic encryption...")
            sns_client = boto3.client('sns', region_name=self.region)
            topics = sns_client.list_topics().get('Topics', [])
            unencrypted_topics = []
            
            for topic in topics:
                topic_arn = topic['TopicArn']
                try:
                    attrs = sns_client.get_topic_attributes(TopicArn=topic_arn)
                    if 'KmsMasterKeyId' not in attrs.get('Attributes', {}):
                        unencrypted_topics.append({
                            'TopicArn': topic_arn.split(':')[-1],
                            'FullArn': topic_arn
                        })
                except:
                    continue
            
            logger.info(f"Found {len(unencrypted_topics)} unencrypted SNS topics")
            return unencrypted_topics
        except Exception as e:
            logger.error(f"Error checking SNS topics: {str(e)}")
            return []
    
    def check_s3_versioning(self):
        """Check for S3 buckets without versioning enabled"""
        try:
            logger.info("Checking S3 versioning...")
            buckets = self.s3.list_buckets().get('Buckets', [])
            no_versioning = []
            
            for bucket in buckets:
                try:
                    bucket_name = bucket['Name']
                    versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                    status = versioning.get('Status', 'Disabled')
                    
                    if status != 'Enabled':
                        no_versioning.append({
                            'BucketName': bucket_name,
                            'VersioningStatus': status,
                            'Created': bucket.get('CreationDate', 'Unknown').strftime('%Y-%m-%d') if bucket.get('CreationDate') != 'Unknown' else 'Unknown'
                        })
                except Exception:
                    continue
            
            logger.info(f"Found {len(no_versioning)} buckets without versioning")
            return no_versioning
        except Exception as e:
            logger.error(f"Error checking S3 versioning: {str(e)}")
            return []
    
    def check_rds_public_access(self):
        """Check for RDS instances with public access"""
        try:
            logger.info("Checking RDS public access...")
            instances = self.rds.describe_db_instances().get('DBInstances', [])
            public_instances = []
            
            for db in instances:
                if db.get('PubliclyAccessible', False):
                    public_instances.append({
                        'DBInstanceIdentifier': db['DBInstanceIdentifier'],
                        'Engine': db.get('Engine', 'unknown'),
                        'EngineVersion': db.get('EngineVersion', 'N/A'),
                        'MultiAZ': db.get('MultiAZ', False)
                    })
            
            logger.info(f"Found {len(public_instances)} publicly accessible RDS instances")
            return public_instances
        except Exception as e:
            logger.error(f"Error checking RDS public access: {str(e)}")
            return []
    
    def check_ec2_public_ip(self):
        """Check for EC2 instances with public IPs in private subnets"""
        try:
            logger.info("Checking EC2 public IPs...")
            reservations = self.ec2.describe_instances().get('Reservations', [])
            public_instances = []
            
            for res in reservations:
                for inst in res.get('Instances', []):
                    if inst.get('State', {}).get('Name') == 'running':
                        public_ip = inst.get('PublicIpAddress')
                        if public_ip:
                            public_instances.append({
                                'InstanceId': inst['InstanceId'],
                                'PublicIP': public_ip,
                                'InstanceType': inst.get('InstanceType', 'N/A'),
                                'SubnetId': inst.get('SubnetId', 'N/A')
                            })
            
            logger.info(f"Found {len(public_instances)} EC2 instances with public IPs")
            return public_instances
        except Exception as e:
            logger.error(f"Error checking EC2 public IPs: {str(e)}")
            return []
    
    def check_root_account_mfa(self):
        """Check if root account has MFA enabled"""
        try:
            logger.info("Checking root account MFA...")
            iam = boto3.client('iam')
            summary = iam.get_account_summary()
            
            account_mfa_enabled = summary['SummaryMap'].get('AccountMFAEnabled', 0)
            
            if account_mfa_enabled == 0:
                return [{
                    'Issue': 'Root account MFA not enabled',
                    'Risk': 'Critical - Root account has full access',
                    'AccountMFAEnabled': False
                }]
            
            logger.info("Root account MFA is enabled")
            return []
        except Exception as e:
            logger.error(f"Error checking root MFA: {str(e)}")
            return []

    def check_cloudtrail_logging(self):
        """Check for CloudTrail logging and encryption issues"""
        try:
            logger.info("Checking CloudTrail logging...")
            cloudtrail = boto3.client('cloudtrail', region_name=self.region)
            trails = cloudtrail.describe_trails().get('trailList', [])
            issues = []
            
            for trail in trails:
                trail_name = trail['Name']
                trail_arn = trail.get('TrailARN', '')
                
                # Get trail status
                try:
                    status = cloudtrail.get_trail_status(Name=trail_arn)
                    is_logging = status.get('IsLogging', False)
                except:
                    is_logging = False
                
                # Check encryption
                kms_key_id = trail.get('KmsKeyId', None)
                
                # Check log file validation
                log_validation = trail.get('LogFileValidationEnabled', False)
                
                problems = []
                if not is_logging:
                    problems.append('Logging disabled')
                if not kms_key_id:
                    problems.append('Not encrypted')
                if not log_validation:
                    problems.append('No log validation')
                
                if problems:
                    issues.append({
                        'TrailName': trail_name,
                        'IsLogging': is_logging,
                        'Encrypted': bool(kms_key_id),
                        'LogValidation': log_validation,
                        'Issues': ', '.join(problems)
                    })
            
            logger.info(f"Found {len(issues)} CloudTrail issues")
            return issues
        except Exception as e:
            logger.error(f"Error checking CloudTrail: {str(e)}")
            return []

    def check_sqs_queue_encryption(self):
        """Check for SQS queues without encryption"""
        try:
            logger.info("Checking SQS queue encryption...")
            sqs_client = boto3.client('sqs', region_name=self.region)
            queues = sqs_client.list_queues().get('QueueUrls', [])
            unencrypted_queues = []
            
            for queue_url in queues:
                try:
                    attrs = sqs_client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=['KmsMasterKeyId']
                    )
                    if 'KmsMasterKeyId' not in attrs.get('Attributes', {}):
                        queue_name = queue_url.split('/')[-1]
                        unencrypted_queues.append({
                            'QueueName': queue_name,
                            'QueueUrl': queue_url
                        })
                except:
                    continue
            
            logger.info(f"Found {len(unencrypted_queues)} unencrypted SQS queues")
            return unencrypted_queues
        except Exception as e:
            logger.error(f"Error checking SQS queues: {str(e)}")
            return []

    def check_parameter_store(self, days=60):
        """Check for unused/stale Parameter Store parameters not modified in 60+ days"""
        try:
            logger.info("Checking Parameter Store...")
            cutoff = utcnow() - timedelta(days=days)
            paginator = self.ssm.get_paginator('describe_parameters')
            stale_params = []
            for page in paginator.paginate():
                for param in page.get('Parameters', []):
                    try:
                        desc = self.ssm.get_parameter_history(Name=param['Name'], MaxResults=1)
                        if desc.get('Parameters'):
                            last_mod = desc['Parameters'][0]['LastModifiedDate']
                            days_old = (utcnow() - last_mod).days
                            if last_mod < cutoff:
                                stale_params.append({
                                    'Name': param['Name'],
                                    'Type': param.get('Type', 'Unknown'),
                                    'DaysOld': days_old,
                                    'LastModified': last_mod.strftime('%Y-%m-%d')
                                })
                    except Exception:
                        continue
            logger.info(f"Found {len(stale_params)} stale parameters (not modified in {days}+ days)")
            return stale_params
        except Exception as e:
            logger.error(f"Error checking Parameter Store: {str(e)}")
            return []
    
    def check_iam_password_policy(self):
        """Check IAM password policy compliance (CIS, PCI-DSS, HIPAA)"""
        try:
            logger.info("Checking IAM password policy...")
            policy = self.iam.get_account_password_policy()['PasswordPolicy']
            issues = []
            
            # CIS/PCI-DSS/HIPAA requirements
            if policy.get('MinimumPasswordLength', 0) < 14:
                issues.append('Password length < 14 characters')
            if not policy.get('RequireUppercaseCharacters', False):
                issues.append('No uppercase requirement')
            if not policy.get('RequireLowercaseCharacters', False):
                issues.append('No lowercase requirement')
            if not policy.get('RequireNumbers', False):
                issues.append('No number requirement')
            if not policy.get('RequireSymbols', False):
                issues.append('No symbol requirement')
            if policy.get('MaxPasswordAge', 0) == 0 or policy.get('MaxPasswordAge', 0) > 90:
                issues.append('Password expiry > 90 days or disabled')
            if policy.get('PasswordReusePrevention', 0) < 24:
                issues.append('Password reuse prevention < 24')
            
            if issues:
                return [{
                    'PolicyIssues': ', '.join(issues),
                    'MinLength': policy.get('MinimumPasswordLength', 0),
                    'MaxAge': policy.get('MaxPasswordAge', 0),
                    'ReusePrevent': policy.get('PasswordReusePrevention', 0)
                }]
            
            logger.info("IAM password policy is compliant")
            return []
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return [{'PolicyIssues': 'No password policy configured', 'MinLength': 0, 'MaxAge': 0, 'ReusePrevent': 0}]
            logger.error(f"Error checking password policy: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Error checking password policy: {str(e)}")
            return []
    
    def check_s3_bucket_logging(self):
        """Check S3 buckets without access logging (PCI-DSS, HIPAA)"""
        try:
            logger.info("Checking S3 bucket logging...")
            buckets = self.s3.list_buckets().get('Buckets', [])
            no_logging = []
            
            for bucket in buckets:
                try:
                    bucket_name = bucket['Name']
                    logging = self.s3.get_bucket_logging(Bucket=bucket_name)
                    
                    if 'LoggingEnabled' not in logging:
                        no_logging.append({
                            'BucketName': bucket_name,
                            'Created': bucket.get('CreationDate', 'Unknown').strftime('%Y-%m-%d') if bucket.get('CreationDate') != 'Unknown' else 'Unknown'
                        })
                except Exception:
                    continue
            
            logger.info(f"Found {len(no_logging)} buckets without access logging")
            return no_logging
        except Exception as e:
            logger.error(f"Error checking S3 bucket logging: {str(e)}")
            return []
    
    def check_rds_multi_az(self):
        """Check RDS instances without Multi-AZ (HIPAA, PCI-DSS)"""
        try:
            logger.info("Checking RDS Multi-AZ...")
            instances = self.rds.describe_db_instances().get('DBInstances', [])
            no_multi_az = []
            
            for db in instances:
                if not db.get('MultiAZ', False):
                    no_multi_az.append({
                        'DBInstanceIdentifier': db['DBInstanceIdentifier'],
                        'Engine': db.get('Engine', 'unknown'),
                        'AvailabilityZone': db.get('AvailabilityZone', 'N/A'),
                        'Status': db.get('DBInstanceStatus', 'unknown')
                    })
            
            logger.info(f"Found {len(no_multi_az)} RDS instances without Multi-AZ")
            return no_multi_az
        except Exception as e:
            logger.error(f"Error checking RDS Multi-AZ: {str(e)}")
            return []
    
    def check_rds_backup_retention(self, min_days=7):
        """Check RDS backup retention period (HIPAA, PCI-DSS)"""
        try:
            logger.info("Checking RDS backup retention...")
            instances = self.rds.describe_db_instances().get('DBInstances', [])
            insufficient_retention = []
            
            for db in instances:
                retention = db.get('BackupRetentionPeriod', 0)
                if retention < min_days:
                    insufficient_retention.append({
                        'DBInstanceIdentifier': db['DBInstanceIdentifier'],
                        'Engine': db.get('Engine', 'unknown'),
                        'RetentionDays': retention,
                        'Required': min_days
                    })
            
            logger.info(f"Found {len(insufficient_retention)} RDS instances with insufficient backup retention")
            return insufficient_retention
        except Exception as e:
            logger.error(f"Error checking RDS backup retention: {str(e)}")
            return []
    
    def check_s3_mfa_delete(self):
        """Check S3 buckets without MFA Delete enabled (CIS, PCI-DSS)"""
        try:
            logger.info("Checking S3 MFA Delete...")
            buckets = self.s3.list_buckets().get('Buckets', [])
            no_mfa_delete = []
            
            for bucket in buckets:
                try:
                    bucket_name = bucket['Name']
                    versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                    
                    # Check if versioning is enabled and MFA Delete is enabled
                    if versioning.get('Status') == 'Enabled' and versioning.get('MFADelete') != 'Enabled':
                        no_mfa_delete.append({
                            'BucketName': bucket_name,
                            'VersioningStatus': versioning.get('Status', 'Disabled'),
                            'MFADelete': versioning.get('MFADelete', 'Disabled')
                        })
                except Exception:
                    continue
            
            logger.info(f"Found {len(no_mfa_delete)} buckets without MFA Delete")
            return no_mfa_delete
        except Exception as e:
            logger.error(f"Error checking S3 MFA Delete: {str(e)}")
            return []
    
    def check_iam_user_mfa(self):
        """Check IAM users without MFA enabled (CIS, PCI-DSS, HIPAA, NIST)"""
        try:
            logger.info("Checking IAM user MFA...")
            users = self.iam.list_users().get('Users', [])
            no_mfa = []
            
            for user in users:
                user_name = user['UserName']
                try:
                    # Check if user has MFA devices
                    mfa_devices = self.iam.list_mfa_devices(UserName=user_name).get('MFADevices', [])
                    
                    # Check if user has console access
                    try:
                        self.iam.get_login_profile(UserName=user_name)
                        has_console = True
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'NoSuchEntity':
                            has_console = False
                        else:
                            has_console = False
                    
                    # Flag users with console access but no MFA
                    if has_console and len(mfa_devices) == 0:
                        no_mfa.append({
                            'UserName': user_name,
                            'ConsoleAccess': 'Yes',
                            'MFADevices': 0,
                            'CreatedDate': user.get('CreateDate', 'Unknown').strftime('%Y-%m-%d') if user.get('CreateDate') != 'Unknown' else 'Unknown'
                        })
                except Exception:
                    continue
            
            logger.info(f"Found {len(no_mfa)} users without MFA")
            return no_mfa
        except Exception as e:
            logger.error(f"Error checking IAM user MFA: {str(e)}")
            return []
    
    def check_iam_access_key_rotation(self, days=90):
        """Check IAM access keys older than 90 days (CIS, PCI-DSS, HIPAA)"""
        try:
            logger.info("Checking IAM access key rotation...")
            cutoff = utcnow() - timedelta(days=days)
            users = self.iam.list_users().get('Users', [])
            old_keys = []
            
            for user in users:
                keys = self.iam.list_access_keys(UserName=user['UserName']).get('AccessKeyMetadata', [])
                for key in keys:
                    if key.get('Status') == 'Active':
                        key_age = (utcnow() - key['CreateDate']).days
                        if key['CreateDate'] < cutoff:
                            old_keys.append({
                                'UserName': user['UserName'],
                                'AccessKeyId': key['AccessKeyId'][-8:],
                                'Age': key_age,
                                'Status': 'Active',
                                'Created': key['CreateDate'].strftime('%Y-%m-%d')
                            })
            
            logger.info(f"Found {len(old_keys)} access keys older than {days} days")
            return old_keys
        except Exception as e:
            logger.error(f"Error checking access key rotation: {str(e)}")
            return []
    
    def check_kms_key_rotation(self):
        """Check KMS keys without automatic rotation (CIS, PCI-DSS, HIPAA)"""
        try:
            logger.info("Checking KMS key rotation...")
            keys = self.kms.list_keys().get('Keys', [])
            no_rotation = []
            
            for key in keys:
                key_id = key['KeyId']
                try:
                    key_metadata = self.kms.describe_key(KeyId=key_id)['KeyMetadata']
                    
                    # Only check customer managed keys
                    if key_metadata.get('KeyManager') == 'CUSTOMER' and key_metadata.get('KeyState') == 'Enabled':
                        rotation_status = self.kms.get_key_rotation_status(KeyId=key_id)
                        
                        if not rotation_status.get('KeyRotationEnabled', False):
                            no_rotation.append({
                                'KeyId': key_id,
                                'KeyArn': key_metadata.get('Arn', 'N/A')[-50:],
                                'CreationDate': key_metadata.get('CreationDate', 'Unknown').strftime('%Y-%m-%d') if key_metadata.get('CreationDate') != 'Unknown' else 'Unknown'
                            })
                except Exception:
                    continue
            
            logger.info(f"Found {len(no_rotation)} KMS keys without rotation")
            return no_rotation
        except Exception as e:
            logger.error(f"Error checking KMS key rotation: {str(e)}")
            return []
    
    def check_config_enabled(self):
        """Check if AWS Config is enabled (CIS, PCI-DSS, HIPAA, NIST)"""
        try:
            logger.info("Checking AWS Config...")
            config_client = boto3.client('config', region_name=self.region)
            
            try:
                recorders = config_client.describe_configuration_recorders().get('ConfigurationRecorders', [])
                recorder_status = config_client.describe_configuration_recorder_status().get('ConfigurationRecordersStatus', [])
                
                if len(recorders) == 0:
                    return [{'Issue': 'AWS Config not configured', 'Status': 'Not Enabled'}]
                
                # Check if recorder is recording
                issues = []
                for status in recorder_status:
                    if not status.get('recording', False):
                        issues.append({
                            'RecorderName': status.get('name', 'Unknown'),
                            'Recording': False,
                            'LastStatus': status.get('lastStatus', 'Unknown')
                        })
                
                if issues:
                    return issues
                
                logger.info("AWS Config is enabled and recording")
                return []
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchConfigurationRecorderException':
                    return [{'Issue': 'AWS Config not configured', 'Status': 'Not Enabled'}]
                raise
        except Exception as e:
            logger.error(f"Error checking AWS Config: {str(e)}")
            return []
    
    def check_guardduty_enabled(self):
        """Check if GuardDuty is enabled (CIS, NIST, HIPAA)"""
        try:
            logger.info("Checking GuardDuty...")
            guardduty = boto3.client('guardduty', region_name=self.region)
            
            detectors = guardduty.list_detectors().get('DetectorIds', [])
            
            if len(detectors) == 0:
                return [{'Issue': 'GuardDuty not enabled', 'Status': 'Disabled'}]
            
            # Check detector status
            issues = []
            for detector_id in detectors:
                detector = guardduty.get_detector(DetectorId=detector_id)
                if detector.get('Status') != 'ENABLED':
                    issues.append({
                        'DetectorId': detector_id,
                        'Status': detector.get('Status', 'Unknown')
                    })
            
            if issues:
                return issues
            
            logger.info("GuardDuty is enabled")
            return []
        except Exception as e:
            logger.error(f"Error checking GuardDuty: {str(e)}")
            return []
    
    def check_securityhub_enabled(self):
        """Check if Security Hub is enabled (CIS, NIST)"""
        try:
            logger.info("Checking Security Hub...")
            securityhub = boto3.client('securityhub', region_name=self.region)
            
            try:
                hub = securityhub.describe_hub()
                if hub.get('HubArn'):
                    logger.info("Security Hub is enabled")
                    return []
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidAccessException':
                    return [{'Issue': 'Security Hub not enabled', 'Status': 'Disabled'}]
                raise
        except Exception as e:
            logger.error(f"Error checking Security Hub: {str(e)}")
            return []
    
    def check_inspector_enabled(self):
        """Check if Amazon Inspector is enabled (CIS, NIST)"""
        try:
            logger.info("Checking Amazon Inspector...")
            inspector = boto3.client('inspector2', region_name=self.region)
            
            try:
                # Check if Inspector is enabled
                response = inspector.batch_get_account_status(accountIds=[self.account_id])
                accounts = response.get('accounts', [])
                
                if not accounts:
                    return [{'Issue': 'Amazon Inspector not enabled', 'Status': 'Disabled'}]
                
                account_status = accounts[0]
                resource_state = account_status.get('resourceState', {})
                
                # Check if EC2 and ECR scanning are enabled
                ec2_enabled = resource_state.get('ec2', {}).get('status') == 'ENABLED'
                ecr_enabled = resource_state.get('ecr', {}).get('status') == 'ENABLED'
                
                if not ec2_enabled and not ecr_enabled:
                    return [{'Issue': 'Amazon Inspector not enabled', 'Status': 'Disabled'}]
                
                logger.info("Amazon Inspector is enabled")
                return []
            except ClientError as e:
                if e.response['Error']['Code'] in ['AccessDeniedException', 'ResourceNotFoundException']:
                    return [{'Issue': 'Amazon Inspector not enabled', 'Status': 'Disabled'}]
                raise
        except Exception as e:
            logger.error(f"Error checking Amazon Inspector: {str(e)}")
            return []
    
    def check_vpc_encryption(self):
        """Check VPCs without encryption enabled (CIS, NIST)"""
        try:
            logger.info("Checking VPC encryption...")
            vpcs = self.ec2.describe_vpcs().get('Vpcs', [])
            unencrypted_vpcs = []
            
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                is_default = vpc.get('IsDefault', False)
                
                # Check if VPC has flow logs with encryption
                try:
                    logs_client = boto3.client('logs', region_name=self.region)
                    flow_logs = self.ec2.describe_flow_logs(
                        Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                    ).get('FlowLogs', [])
                    
                    has_encrypted_logs = False
                    for flow_log in flow_logs:
                        log_group = flow_log.get('LogGroupName')
                        if log_group:
                            try:
                                log_info = logs_client.describe_log_groups(
                                    logGroupNamePrefix=log_group
                                ).get('logGroups', [])
                                
                                if log_info and log_info[0].get('kmsKeyId'):
                                    has_encrypted_logs = True
                                    break
                            except:
                                pass
                    
                    if not has_encrypted_logs:
                        unencrypted_vpcs.append({
                            'VpcId': vpc_id,
                            'IsDefault': 'Yes' if is_default else 'No',
                            'CidrBlock': vpc.get('CidrBlock', 'Unknown'),
                            'Issue': 'VPC flow logs not encrypted with KMS'
                        })
                except Exception as e:
                    logger.debug(f"Error checking VPC {vpc_id} encryption: {e}")
            
            logger.info(f"Found {len(unencrypted_vpcs)} VPCs without encrypted flow logs")
            return unencrypted_vpcs
        except Exception as e:
            logger.error(f"Error checking VPC encryption: {str(e)}")
            return []
    
    def check_ecr_tag_immutability(self):
        """Check ECR repositories without tag immutability enabled (CIS, PCI-DSS)"""
        try:
            logger.info("Checking ECR tag immutability...")
            ecr = boto3.client('ecr', region_name=self.region)
            repositories = ecr.describe_repositories().get('repositories', [])
            mutable_repos = []
            
            for repo in repositories:
                if repo.get('imageTagMutability') != 'IMMUTABLE':
                    mutable_repos.append({
                        'RepositoryName': repo['repositoryName'],
                        'RepositoryUri': repo['repositoryUri'],
                        'ImageTagMutability': repo.get('imageTagMutability', 'MUTABLE'),
                        'CreatedAt': repo.get('createdAt', 'Unknown').strftime('%Y-%m-%d') if isinstance(repo.get('createdAt'), datetime) else 'Unknown',
                        'ImageCount': repo.get('imageCount', 0)
                    })
            
            logger.info(f"Found {len(mutable_repos)} ECR repositories with mutable tags")
            return mutable_repos
        except Exception as e:
            logger.error(f"Error checking ECR tag immutability: {str(e)}")
            return []
    
    def check_ebs_default_encryption(self):
        """Check if EBS encryption by default is enabled (CIS, PCI-DSS, HIPAA)"""
        try:
            logger.info("Checking EBS default encryption...")
            result = self.ec2.get_ebs_encryption_by_default()
            
            if not result.get('EbsEncryptionByDefault', False):
                return [{
                    'Issue': 'EBS encryption by default is disabled',
                    'Region': self.region,
                    'Status': 'Disabled'
                }]
            
            logger.info("EBS default encryption is enabled")
            return []
        except Exception as e:
            logger.error(f"Error checking EBS default encryption: {str(e)}")
            return []
    
    def check_rds_deletion_protection(self):
        """Check RDS instances without deletion protection (HIPAA, PCI-DSS)"""
        try:
            logger.info("Checking RDS deletion protection...")
            instances = self.rds.describe_db_instances().get('DBInstances', [])
            no_protection = []
            
            for db in instances:
                if not db.get('DeletionProtection', False):
                    no_protection.append({
                        'DBInstanceIdentifier': db['DBInstanceIdentifier'],
                        'Engine': db.get('Engine', 'unknown'),
                        'DeletionProtection': False,
                        'Status': db.get('DBInstanceStatus', 'unknown')
                    })
            
            logger.info(f"Found {len(no_protection)} RDS instances without deletion protection")
            return no_protection
        except Exception as e:
            logger.error(f"Error checking RDS deletion protection: {str(e)}")
            return []

    def score_findings(self, report):
        scored = []
        for key, findings in report.items():
            severity = SEVERITY_MAP.get(key, 0)
            count = len(findings) if isinstance(findings, list) else 0
            if count > 0:
                scored.append({'check': key, 'severity': severity, 'count': count, 'items': findings})
        scored.sort(key=lambda x: (x['severity'], x['count']), reverse=True)
        return scored

    def run_audit(self, parallel=True):
        """Run all security checks (optionally in parallel)"""
        logger.info("🚀 Starting AWS security audit...")
        
        checks = {
            'EC2_SG_OPEN_0_0_0_0': self.check_ec2_security_groups,
            'S3_PUBLIC_BUCKET': self.check_s3_public_buckets,
            'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS': self.check_s3_bucket_policies_excessive_permissions,
            'IAM_USER_INACTIVE': self.check_iam_users_inactive,
            'IAM_ACCESS_KEY_UNUSED': self.check_iam_access_keys_unused,
            'EBS_UNENCRYPTED': self.check_ebs_encryption,
            'RDS_UNENCRYPTED': self.check_rds_encryption,
            'AURORA_UNENCRYPTED': self.check_aurora_encryption,
            'IAM_ROLE_UNUSED': self.check_iam_roles_unused,
            'BACKUP_VAULT_UNENCRYPTED': self.check_backup_vaults_encryption,
            'EC2_NO_IMDSV2': self.check_ec2_imdsv2,
            'EC2_UNUSED_KEY_PAIR': self.check_unused_key_pairs,
            'ECS_ENCRYPTION_ISSUE': self.check_ecs_encryption_issues,
            'API_GW_LOG_UNENCRYPTED': self.check_api_gateway_log_encryption,
            'CLOUDFRONT_ENCRYPTION_ISSUE': self.check_cloudfront_encryption,
            'RDS_AURORA_BACKUP_UNENCRYPTED': self.check_rds_aurora_backups_encrypted,
            'UNUSED_KMS_KEYS': self.check_unused_kms_keys,
            'UNUSED_SECRETS': self.check_unused_secrets,
            'PARAMETER_STORE_ISSUE': self.check_parameter_store,
            'GUARDDUTY_DISABLED': self.check_guardduty_enabled,
            'SECURITYHUB_DISABLED': self.check_securityhub_enabled,
            'INSPECTOR_DISABLED': self.check_inspector_enabled,
            'VPC_LOGS_UNENCRYPTED': self.check_vpc_encryption,
            'ECR_TAG_MUTABLE': self.check_ecr_tag_immutability,
        }
        
        report = {}
        
        if parallel:
            # Run checks in parallel for faster execution
            with ThreadPoolExecutor(max_workers=10) as executor:
                future_to_check = {executor.submit(func): name for name, func in checks.items()}
                for future in as_completed(future_to_check):
                    check_name = future_to_check[future]
                    try:
                        report[check_name] = future.result()
                    except Exception as e:
                        logger.error(f"Check {check_name} failed: {str(e)}")
                        report[check_name] = []
        else:
            # Run checks sequentially
            for name, func in checks.items():
                try:
                    report[name] = func()
                except Exception as e:
                    logger.error(f"Check {name} failed: {str(e)}")
                    report[name] = []
        
        logger.info("✅ Audit complete!")
        return report

def get_finding_details(check_name):
    """Get comprehensive details for each security finding"""
    details = {
        'EC2_SG_OPEN_0_0_0_0': {
            'recommendation': 'Restrict security groups to specific IP ranges only',
            'impact': 'Critical - Exposes resources to internet attacks, unauthorized access, and data breaches',
            'timeline': '24 hours',
            'solution': '1. Identify legitimate IP ranges\n2. Remove 0.0.0.0/0 rules\n3. Add specific CIDR blocks\n4. Use AWS Systems Manager Session Manager instead of SSH'
        },
        'S3_PUBLIC_BUCKET': {
            'recommendation': 'Enable S3 Block Public Access and remove public ACLs',
            'impact': 'Critical - Risk of data exposure, compliance violations, unauthorized data access',
            'timeline': '24-48 hours',
            'solution': '1. Enable Block Public Access at bucket level\n2. Remove public ACLs and policies\n3. Use CloudFront with OAI for public content\n4. Use presigned URLs for temporary access'
        },
        'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS': {
            'recommendation': 'Apply least privilege principle to bucket policies',
            'impact': 'High - Potential unauthorized access to sensitive data',
            'timeline': '1 week',
            'solution': '1. Review bucket policy for wildcards (*)\n2. Replace with specific IAM roles/users\n3. Add condition statements for IP restrictions\n4. Test access before applying'
        },
        'IAM_USER_INACTIVE': {
            'recommendation': 'Disable or delete inactive IAM users',
            'impact': 'Critical - Inactive accounts are prime targets for attackers',
            'timeline': '48 hours',
            'solution': '1. Contact user to confirm account not needed\n2. Disable console access\n3. Deactivate access keys\n4. Delete user after confirmation'
        },
        'IAM_ACCESS_KEY_UNUSED': {
            'recommendation': 'Delete unused access keys and rotate active ones',
            'impact': 'High - Unused keys can be compromised without detection',
            'timeline': '1 week',
            'solution': '1. Verify key is unused (check CloudTrail)\n2. Delete unused key\n3. For active keys: create new, update apps, delete old\n4. Implement 90-day rotation policy'
        },
        'IAM_ROLE_UNUSED': {
            'recommendation': 'Delete unused IAM roles to reduce attack surface',
            'impact': 'Low - Reduces potential privilege escalation paths',
            'timeline': '2 weeks',
            'solution': '1. Verify role is unused\n2. Review attached policies\n3. Detach policies\n4. Delete role (keep AWS service-linked roles)'
        },
        'EBS_UNENCRYPTED': {
            'recommendation': 'Enable encryption for all EBS volumes',
            'impact': 'High - Unencrypted data at rest violates compliance',
            'timeline': '1-2 weeks',
            'solution': '1. Create snapshot\n2. Copy snapshot with encryption\n3. Create encrypted volume\n4. Stop instance, swap volumes\n5. Enable encryption by default'
        },
        'RDS_UNENCRYPTED': {
            'recommendation': 'Enable encryption at rest for RDS instances',
            'impact': 'High - Database contains sensitive data requiring encryption',
            'timeline': '1-2 weeks',
            'solution': '1. Create snapshot\n2. Copy with encryption\n3. Restore to new encrypted instance\n4. Update connection strings\n5. Delete old instance'
        },
        'AURORA_UNENCRYPTED': {
            'recommendation': 'Enable encryption for Aurora clusters',
            'impact': 'High - Cluster data must be encrypted for compliance',
            'timeline': '1-2 weeks',
            'solution': '1. Create cluster snapshot\n2. Copy with encryption\n3. Restore to new encrypted cluster\n4. Update endpoints\n5. Migrate replicas'
        },
        'RDS_AURORA_BACKUP_UNENCRYPTED': {
            'recommendation': 'Enable backup encryption with KMS',
            'impact': 'Critical - Backup data exposure risk',
            'timeline': '24 hours',
            'solution': '1. Modify DB to enable backup encryption\n2. Specify KMS key\n3. New backups encrypted automatically\n4. Delete old unencrypted backups'
        },
        'EC2_NO_IMDSV2': {
            'recommendation': 'Enforce IMDSv2 to prevent SSRF attacks',
            'impact': 'High - Vulnerable to Server-Side Request Forgery attacks',
            'timeline': '1 week',
            'solution': '1. Test application compatibility\n2. Modify metadata options to require tokens\n3. Update application code\n4. Enable IMDSv2 by default'
        },
        'EC2_UNUSED_KEY_PAIR': {
            'recommendation': 'Delete unused EC2 key pairs',
            'impact': 'Medium - Reduces risk of unauthorized instance access',
            'timeline': '1 week',
            'solution': '1. Verify no instances use the key\n2. Check automation scripts\n3. Delete key pair\n4. Document deletion'
        },
        'BACKUP_VAULT_UNENCRYPTED': {
            'recommendation': 'Enable KMS encryption for backup vaults',
            'impact': 'High - Backup data must be encrypted',
            'timeline': '1 week',
            'solution': '1. Create new encrypted vault\n2. Update backup plans\n3. Copy existing backups\n4. Delete old vault'
        },
        'ECS_ENCRYPTION_ISSUE': {
            'recommendation': 'Enable encryption for ECS task storage',
            'impact': 'High - Container data and secrets must be encrypted',
            'timeline': '1 week',
            'solution': '1. Update task definition for encrypted EFS\n2. Enable encryption for EBS volumes\n3. Store secrets in Secrets Manager\n4. Reference secrets in task definition'
        },
        'API_GW_LOG_UNENCRYPTED': {
            'recommendation': 'Enable KMS encryption for API Gateway logs',
            'impact': 'High - API logs may contain sensitive data',
            'timeline': '3 days',
            'solution': '1. Create/identify KMS key\n2. Associate key with log group\n3. Update API Gateway stage settings\n4. Verify log encryption'
        },
        'CLOUDFRONT_ENCRYPTION_ISSUE': {
            'recommendation': 'Enforce HTTPS-only for CloudFront distributions',
            'impact': 'High - Data in transit must be encrypted',
            'timeline': '3 days',
            'solution': '1. Update viewer protocol to redirect-to-https\n2. Configure custom SSL certificate\n3. Set minimum TLS to v1.2\n4. Test all behaviors'
        },
        'UNUSED_KMS_KEYS': {
            'recommendation': 'Delete or disable unused KMS keys',
            'impact': 'Low - Reduces costs and management overhead',
            'timeline': '2 weeks',
            'solution': '1. Verify key not used\n2. Check CloudTrail history\n3. Disable key first\n4. Schedule deletion (30-day window)'
        },
        'UNUSED_SECRETS': {
            'recommendation': 'Delete unused secrets from Secrets Manager',
            'impact': 'Medium - Reduces costs and potential exposure',
            'timeline': '1 week',
            'solution': '1. Check last accessed date\n2. Verify not referenced in apps\n3. Delete with 30-day recovery window\n4. Enable rotation for active secrets'
        },
        'PARAMETER_STORE_ISSUE': {
            'recommendation': 'Clean up unused SSM parameters',
            'impact': 'Low - Reduces clutter and potential misuse',
            'timeline': '2 weeks',
            'solution': '1. Review last modified date\n2. Check automation references\n3. Delete unused parameters\n4. Convert to SecureString for sensitive data'
        },
        'SECRETS_UNENCRYPTED': {
            'recommendation': 'Consider using customer-managed KMS keys for Secrets Manager',
            'impact': 'Informational - AWS-managed encryption is enabled by default, custom KMS provides additional control',
            'timeline': 'Optional - Implement based on compliance requirements',
            'solution': '1. Evaluate if custom KMS key is required for compliance\n2. Create customer-managed KMS key if needed\n3. Update secret to use custom KMS key\n4. Note: AWS-managed encryption is already active and secure'
        },
        'SSM_PARAMETERS_UNENCRYPTED': {
            'recommendation': 'Convert String parameters to SecureString for sensitive data',
            'impact': 'Informational - Consider encryption for sensitive configuration values',
            'timeline': 'Optional - Review and convert as needed',
            'solution': '1. Identify parameters containing sensitive data\n2. Create new SecureString parameters with KMS encryption\n3. Update applications to use new parameters\n4. Delete old String parameters after migration'
        },
        'GUARDDUTY_DISABLED': {
            'recommendation': 'Enable Amazon GuardDuty for threat detection',
            'impact': 'High - Missing continuous threat detection and monitoring',
            'timeline': '24 hours',
            'solution': '1. Enable GuardDuty in AWS Console or CLI\n2. Configure findings export to S3\n3. Set up SNS notifications for high severity findings\n4. Review findings regularly'
        },
        'SECURITYHUB_DISABLED': {
            'recommendation': 'Enable AWS Security Hub for centralized security view',
            'impact': 'Medium - Missing centralized security posture management',
            'timeline': '1 week',
            'solution': '1. Enable Security Hub in AWS Console\n2. Enable security standards (CIS, PCI-DSS, etc.)\n3. Integrate with GuardDuty and Inspector\n4. Configure automated remediation'
        },
        'INSPECTOR_DISABLED': {
            'recommendation': 'Enable Amazon Inspector for vulnerability scanning',
            'impact': 'Medium - Missing automated vulnerability assessments',
            'timeline': '1 week',
            'solution': '1. Enable Inspector in AWS Console\n2. Enable EC2 and ECR scanning\n3. Configure scan schedules\n4. Review and remediate findings'
        },
        'VPC_LOGS_UNENCRYPTED': {
            'recommendation': 'Enable KMS encryption for VPC Flow Logs',
            'impact': 'Medium - Network traffic logs may contain sensitive information',
            'timeline': '1 week',
            'solution': '1. Create or identify KMS key for CloudWatch Logs\n2. Update flow log configuration to use KMS encryption\n3. Create new encrypted log group if needed\n4. Migrate existing flow logs to encrypted log group'
        },
        'ECR_TAG_MUTABLE': {
            'recommendation': 'Enable tag immutability for ECR repositories',
            'impact': 'Medium - Prevents image tag overwriting and ensures image integrity',
            'timeline': '3 days',
            'solution': '1. Review repository tagging strategy\n2. Enable tag immutability: aws ecr put-image-tag-mutability --repository-name <name> --image-tag-mutability IMMUTABLE\n3. Update CI/CD pipelines to use unique tags\n4. Test deployment process with immutable tags'
        },
        'S3_VERSIONING_DISABLED': {
            'recommendation': 'Enable versioning for S3 buckets',
            'impact': 'Low - Protects against accidental deletion and provides recovery options',
            'timeline': '1 week',
            'solution': '1. Review bucket contents and retention requirements\n2. Enable versioning: aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled\n3. Configure lifecycle policies to manage old versions\n4. Monitor storage costs'
        },
        'EBS_SNAPSHOT_UNENCRYPTED': {
            'recommendation': 'Enable encryption for EBS snapshots',
            'impact': 'High - Snapshot data must be encrypted for compliance',
            'timeline': '1 week',
            'solution': '1. Copy unencrypted snapshot with encryption enabled\n2. Use encrypted copy for restores\n3. Delete unencrypted snapshot after verification\n4. Enable encryption by default for new snapshots'
        },
        'DYNAMODB_UNENCRYPTED': {
            'recommendation': 'Enable encryption at rest for DynamoDB tables',
            'impact': 'High - Table data must be encrypted for compliance',
            'timeline': '1 week',
            'solution': '1. Create backup of table\n2. Enable encryption at rest (cannot be disabled once enabled)\n3. Choose AWS-managed or customer-managed KMS key\n4. Monitor performance after enabling'
        },
        'RDS_PUBLIC_ACCESS': {
            'recommendation': 'Remove public accessibility from RDS instances',
            'impact': 'Critical - Database exposed to internet attacks',
            'timeline': '24 hours',
            'solution': '1. Modify RDS instance to disable public accessibility\n2. Update security groups to allow only VPC access\n3. Use VPN or Direct Connect for external access\n4. Consider using RDS Proxy for connection management'
        },
        'ROOT_MFA_DISABLED': {
            'recommendation': 'Enable MFA for root account',
            'impact': 'Critical - Root account compromise can destroy entire AWS environment',
            'timeline': 'Immediate',
            'solution': '1. Sign in as root user\n2. Go to IAM > Security credentials\n3. Enable virtual or hardware MFA device\n4. Store backup codes securely'
        },
        'AMI_UNENCRYPTED': {
            'recommendation': 'Enable encryption for AMIs',
            'impact': 'High - AMI snapshots contain sensitive data',
            'timeline': '1 week',
            'solution': '1. Copy AMI with encryption enabled\n2. Use encrypted AMI for new instances\n3. Deregister unencrypted AMI\n4. Enable EBS encryption by default'
        },
        'VPC_NO_FLOW_LOGS': {
            'recommendation': 'Enable VPC Flow Logs for network monitoring',
            'impact': 'Medium - Missing network traffic visibility for security analysis',
            'timeline': '3 days',
            'solution': '1. Create CloudWatch log group or S3 bucket\n2. Enable VPC Flow Logs for all VPCs\n3. Configure log format and filters\n4. Set up monitoring and alerts'
        },
        'LAMBDA_PUBLIC_ACCESS': {
            'recommendation': 'Remove public access from Lambda functions',
            'impact': 'Critical - Function can be invoked by anyone on internet',
            'timeline': '24 hours',
            'solution': '1. Review function resource policy\n2. Remove Principal: "*" statements\n3. Use specific IAM roles or API Gateway\n4. Enable function URL authentication if needed'
        },
        'ELB_NO_LOGGING': {
            'recommendation': 'Enable access logging for load balancers',
            'impact': 'Medium - Missing audit trail for troubleshooting and security',
            'timeline': '3 days',
            'solution': '1. Create S3 bucket for logs\n2. Enable access logs on load balancer\n3. Configure log retention policies\n4. Set up log analysis tools'
        },
        'SNS_UNENCRYPTED': {
            'recommendation': 'Enable KMS encryption for SNS topics',
            'impact': 'High - Messages may contain sensitive data',
            'timeline': '1 week',
            'solution': '1. Create or identify KMS key\n2. Update SNS topic to use KMS encryption\n3. Update IAM policies to allow kms:Decrypt\n4. Test message delivery'
        },
        'SQS_UNENCRYPTED': {
            'recommendation': 'Enable KMS encryption for SQS queues',
            'impact': 'High - Queue messages may contain sensitive data',
            'timeline': '1 week',
            'solution': '1. Create or identify KMS key\n2. Update queue to use KMS encryption\n3. Update IAM policies for producers/consumers\n4. Test message processing'
        },
        'CLOUDTRAIL_ISSUES': {
            'recommendation': 'Enable and properly configure CloudTrail',
            'impact': 'Critical - Missing audit logs for compliance and security investigations',
            'timeline': '24 hours',
            'solution': '1. Enable CloudTrail in all regions\n2. Enable log file validation\n3. Configure S3 bucket with encryption\n4. Set up CloudWatch Logs integration'
        },
        'EC2_PUBLIC_IP': {
            'recommendation': 'Review EC2 instances with public IPs',
            'impact': 'High - Instances directly exposed to internet',
            'timeline': '1 week',
            'solution': '1. Identify if public IP is necessary\n2. Use NAT Gateway for outbound traffic\n3. Place instances in private subnets\n4. Use load balancers for inbound traffic'
        },
    }
    return details.get(check_name, {
        'recommendation': 'Review and remediate this security finding',
        'impact': 'Varies - Assess based on resource sensitivity',
        'timeline': '2 weeks',
        'solution': 'Follow AWS security best practices'
    })

def get_recommendation(check_name):
    """Get security recommendation for each check (backward compatibility)"""
    details = get_finding_details(check_name)
    return details.get('recommendation', 'Review and remediate this security finding')

def get_policy_example(check_name):
    """Get example policy for specific checks"""
    examples = {
        'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS': '''{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "LeastPrivilegeExample",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::ACCOUNT-ID:role/SpecificRole"},
    "Action": ["s3:GetObject", "s3:PutObject"],
    "Resource": "arn:aws:s3:::bucket-name/prefix/*",
    "Condition": {
      "IpAddress": {"aws:SourceIp": "203.0.113.0/24"},
      "StringEquals": {"aws:PrincipalOrgID": "o-xxxxxxxxxx"}
    }
  }]
}'''
    }
    return examples.get(check_name, '')

def get_remediation_command(check_name, resource_id=None):
    """Get AWS CLI remediation command for each check"""
    commands = {
        'EC2_SG_OPEN_0_0_0_0': f'aws ec2 revoke-security-group-ingress --group-id {resource_id or "sg-xxxxx"} --ip-permissions IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{{CidrIp=0.0.0.0/0}}]',
        'S3_PUBLIC_BUCKET': f'aws s3api put-public-access-block --bucket {resource_id or "bucket-name"} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"',
        'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS': f'Review policy and replace wildcards: 1) Replace Principal:"*" with specific IAM roles/users, 2) Replace Action:"s3:*" with specific actions (s3:GetObject, s3:PutObject), 3) Add Condition blocks for IP/VPC restrictions',
        'IAM_USER_INACTIVE': f'aws iam delete-login-profile --user-name {resource_id or "username"} && aws iam update-user --user-name {resource_id or "username"} --no-password-reset-required',
        'IAM_ACCESS_KEY_UNUSED': f'aws iam delete-access-key --user-name {resource_id or "username"} --access-key-id AKIAIOSFODNN7EXAMPLE',
        'IAM_ROLE_UNUSED': f'aws iam delete-role --role-name {resource_id or "role-name"}',
        'EBS_UNENCRYPTED': f'aws ec2 create-snapshot --volume-id {resource_id or "vol-xxxxx"} --description "Backup before encryption" && aws ec2 copy-snapshot --source-snapshot-id snap-xxxxx --encrypted --kms-key-id alias/aws/ebs',
        'RDS_UNENCRYPTED': f'aws rds create-db-snapshot --db-instance-identifier {resource_id or "db-instance"} --db-snapshot-identifier encrypted-snapshot && aws rds restore-db-instance-from-db-snapshot --db-instance-identifier new-encrypted-db --db-snapshot-identifier encrypted-snapshot --storage-encrypted --kms-key-id alias/aws/rds',
        'AURORA_UNENCRYPTED': f'aws rds create-db-cluster-snapshot --db-cluster-identifier {resource_id or "cluster-id"} --db-cluster-snapshot-identifier encrypted-snapshot && aws rds restore-db-cluster-from-snapshot --db-cluster-identifier new-encrypted-cluster --snapshot-identifier encrypted-snapshot --storage-encrypted --kms-key-id alias/aws/rds',
        'RDS_AURORA_BACKUP_UNENCRYPTED': f'aws rds modify-db-instance --db-instance-identifier {resource_id or "db-instance"} --backup-retention-period 7 --storage-encrypted --kms-key-id alias/aws/rds --apply-immediately',
        'EC2_NO_IMDSV2': f'aws ec2 modify-instance-metadata-options --instance-id {resource_id or "i-xxxxx"} --http-tokens required --http-put-response-hop-limit 1',
        'EC2_UNUSED_KEY_PAIR': f'aws ec2 delete-key-pair --key-name {resource_id or "key-pair-name"}',
        'BACKUP_VAULT_UNENCRYPTED': f'aws backup create-backup-vault --backup-vault-name encrypted-vault --encryption-key-arn arn:aws:kms:region:account:key/key-id',
        'ECS_ENCRYPTION_ISSUE': f'aws ecs register-task-definition --family {resource_id or "task-family"} --container-definitions file://task-def.json --volumes name=efs-volume,efsVolumeConfiguration={{fileSystemId=fs-xxxxx,transitEncryption=ENABLED}}',
        'API_GW_LOG_UNENCRYPTED': f'aws logs associate-kms-key --log-group-name /aws/apigateway/{resource_id or "api-name"} --kms-key-id arn:aws:kms:region:account:key/key-id',
        'CLOUDFRONT_ENCRYPTION_ISSUE': f'aws cloudfront update-distribution --id {resource_id or "E1234567890ABC"} --distribution-config file://config.json (set ViewerProtocolPolicy=redirect-to-https)',
        'UNUSED_KMS_KEYS': f'aws kms schedule-key-deletion --key-id {resource_id or "key-id"} --pending-window-in-days 30',
        'UNUSED_SECRETS': f'aws secretsmanager delete-secret --secret-id {resource_id or "secret-name"} --recovery-window-in-days 30',
        'PARAMETER_STORE_ISSUE': f'aws ssm delete-parameter --name {resource_id or "/path/to/parameter"}',
    }
    return commands.get(check_name, 'aws <service> <action> --resource-id <value>')

def get_aws_documentation_url(check_name):
    """Get AWS documentation URL for each check"""
    urls = {
        'EC2_SG_OPEN_0_0_0_0': 'https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html',
        'S3_PUBLIC_BUCKET': 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html',
        'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS': 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html',
        'IAM_USER_INACTIVE': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
        'IAM_ACCESS_KEY_UNUSED': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html',
        'IAM_ROLE_UNUSED': 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html',
        'EBS_UNENCRYPTED': 'https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html',
        'RDS_UNENCRYPTED': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
        'AURORA_UNENCRYPTED': 'https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Overview.Encryption.html',
        'RDS_AURORA_BACKUP_UNENCRYPTED': 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html',
        'EC2_NO_IMDSV2': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
        'EC2_UNUSED_KEY_PAIR': 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html',
        'BACKUP_VAULT_UNENCRYPTED': 'https://docs.aws.amazon.com/aws-backup/latest/devguide/encryption.html',
        'ECS_ENCRYPTION_ISSUE': 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/security-ecs.html',
        'API_GW_LOG_UNENCRYPTED': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/security-best-practices.html',
        'CLOUDFRONT_ENCRYPTION_ISSUE': 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html',
        'UNUSED_KMS_KEYS': 'https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html',
        'UNUSED_SECRETS': 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/best-practices.html',
        'PARAMETER_STORE_ISSUE': 'https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-best-practices.html',
    }
    return urls.get(check_name, 'https://aws.amazon.com/security/security-resources/')

def get_security_quote():
    """Get a random AWS Shared Responsibility Model security quote"""
    quotes = [
        {
            'text': 'AWS Shared Responsibility: AWS secures the infrastructure. You secure your data, applications, and access controls.',
            'author': 'AWS Shared Responsibility Model'
        },
        {
            'text': 'Security OF the cloud is AWS responsibility. Security IN the cloud is YOUR responsibility.',
            'author': 'AWS Shared Responsibility Model'
        },
        {
            'text': 'AWS manages physical security, network infrastructure, and hypervisor. You manage OS patches, encryption, IAM, and security groups.',
            'author': 'AWS Shared Responsibility Model'
        },
        {
            'text': 'AWS provides the tools. You must configure them correctly. Encryption, MFA, and least privilege are YOUR responsibility.',
            'author': 'AWS Shared Responsibility Model'
        },
        {
            'text': 'CloudTrail logging, GuardDuty alerts, and Security Hub findings are useless if you do not act on them. Monitoring is YOUR responsibility.',
            'author': 'AWS Shared Responsibility Model'
        },
        {
            'text': 'AWS secures the hardware. You secure the data. Unencrypted data is YOUR risk, not AWS.',
            'author': 'AWS Shared Responsibility Model'
        },
        {
            'text': 'Public S3 buckets, open security groups, and unused IAM keys are YOUR configuration choices. AWS provides the controls, you must use them.',
            'author': 'AWS Shared Responsibility Model'
        },
        {
            'text': 'AWS patches the hypervisor. You patch the OS. AWS secures the datacenter. You secure the application. Know your responsibilities.',
            'author': 'AWS Shared Responsibility Model'
        },
        {
            'text': 'Root account MFA, IAM password policies, and access key rotation are YOUR responsibility. AWS cannot enforce them for you.',
            'author': 'AWS Shared Responsibility Model'
        },
        {
            'text': 'AWS provides VPCs, NACLs, and security groups. You must configure them correctly. Network security is a shared responsibility.',
            'author': 'AWS Shared Responsibility Model'
        },
        {
            'text': 'Backup encryption, RDS snapshots, and EBS volume encryption are YOUR choices. AWS provides the capability, you must enable it.',
            'author': 'AWS Shared Responsibility Model'
        },
        {
            'text': 'AWS secures the Lambda runtime. You secure the function code, IAM roles, and environment variables. Serverless security is shared.',
            'author': 'AWS Shared Responsibility Model'
        }
    ]
    return random.choice(quotes)

def create_pdf_report(scored_report, region, comparison=None, credentials=None, compliance_frameworks=None):
    """Create a colorful, well-structured PDF report with optional comparison and compliance scoring"""
    from reportlab.lib.pagesizes import letter
    
    # Default to empty list if no frameworks specified
    if compliance_frameworks is None:
        compliance_frameworks = []
    from reportlab.lib import colors
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
    from reportlab.platypus import Table, TableStyle
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    
    # Set default fonts
    default_font = 'Helvetica'
    default_font_bold = 'Helvetica-Bold'
    
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Get account info and additional details using provided credentials
    try:
        # Use provided credentials (from assumed role) or default credentials
        if credentials:
            sts = boto3.client(
                'sts',
                aws_access_key_id=credentials['aws_access_key_id'],
                aws_secret_access_key=credentials['aws_secret_access_key'],
                aws_session_token=credentials['aws_session_token']
            )
            iam = boto3.client(
                'iam',
                aws_access_key_id=credentials['aws_access_key_id'],
                aws_secret_access_key=credentials['aws_secret_access_key'],
                aws_session_token=credentials['aws_session_token']
            )
        else:
            sts = boto3.client('sts')
            iam = boto3.client('iam')
            
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        
        # Try to get account alias (more user-friendly than ARN)
        try:
            aliases = iam.list_account_aliases()
            account_name = aliases['AccountAliases'][0] if aliases.get('AccountAliases') else None
        except:
            account_name = None
        
        user_id = identity.get('UserId', 'Unknown')
    except:
        account_id = 'Unknown'
        account_name = 'Unknown'
        user_id = 'Unknown'
    
    scan_date = utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Calculate risk metrics
    total_findings = sum(entry['count'] for entry in scored_report)
    critical_findings = sum(entry['count'] for entry in scored_report if entry['severity'] == 3)
    high_findings = sum(entry['count'] for entry in scored_report if entry['severity'] == 2)
    medium_findings = sum(entry['count'] for entry in scored_report if entry['severity'] == 1)
    low_findings = sum(entry['count'] for entry in scored_report if entry['severity'] == 0)
    
    # Calculate risk score (0-100)
    risk_score = min(100, (critical_findings * 10) + (high_findings * 5) + (medium_findings * 2) + (low_findings * 0.5))
    
    # Determine risk level
    if risk_score >= 50:
        risk_level = "CRITICAL"
        risk_color = colors.HexColor('#d32f2f')
    elif risk_score >= 30:
        risk_level = "HIGH"
        risk_color = colors.HexColor('#f57c00')
    elif risk_score >= 15:
        risk_level = "MEDIUM"
        risk_color = colors.HexColor('#fbc02d')
    else:
        risk_level = "LOW"
        risk_color = colors.HexColor('#388e3c')
    
    # Severity colors and names
    severity_colors = {
        3: colors.HexColor('#d32f2f'),  # Critical - Red
        2: colors.HexColor('#f57c00'),  # High - Orange
        1: colors.HexColor('#fbc02d'),  # Medium - Yellow
        0: colors.HexColor('#388e3c')   # Low - Green
    }
    # Severity names
    severity_names = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}
    
    def draw_header(canvas_obj, page_num=1):
        """Draw enhanced page header with professional blue/white design"""
        # Header background - Professional blue
        canvas_obj.setFillColor(colors.HexColor('#1565C0'))
        canvas_obj.rect(0, height - 85, width, 85, fill=True, stroke=False)
        
        # Accent line - Light blue
        canvas_obj.setFillColor(colors.HexColor('#42A5F5'))
        canvas_obj.rect(0, height - 90, width, 5, fill=True, stroke=False)
        
        # Shield icon
        canvas_obj.setFillColor(colors.white)
        canvas_obj.setFont(default_font_bold, 28)
        canvas_obj.drawString(50, height - 52, "🛡")
        
        # Title
        canvas_obj.setFillColor(colors.white)
        canvas_obj.setFont(default_font_bold, 24)
        canvas_obj.drawString(95, height - 40, "AWS Security Audit Report")
        
        # Subtitle
        canvas_obj.setFont(default_font, 11)
        canvas_obj.setFillColor(colors.HexColor('#E3F2FD'))
        canvas_obj.drawString(95, height - 60, f"Region: {region}")
        
        # Page number in corner
        canvas_obj.setFillColor(colors.white)
        canvas_obj.setFont(default_font, 10)
        canvas_obj.drawRightString(width - 50, height - 45, f"Page {page_num}")
        
    def draw_footer(canvas_obj):
        """Draw page footer with professional blue/white design"""
        # Footer background - Light blue/white
        canvas_obj.setFillColor(colors.HexColor('#FAFAFA'))
        canvas_obj.rect(0, 0, width, 70, fill=True, stroke=False)
        
        # Top border line - Professional blue
        canvas_obj.setStrokeColor(colors.HexColor('#1565C0'))
        canvas_obj.setLineWidth(2)
        canvas_obj.line(0, 70, width, 70)
        
        # Footer text - clean and simple
        canvas_obj.setFillColor(colors.HexColor('#424242'))
        canvas_obj.setFont(default_font, 9)
        
        # Left side - Account info
        if account_name:
            canvas_obj.drawString(50, 42, f"Account: {account_id} ({account_name})")
        else:
            canvas_obj.drawString(50, 42, f"Account: {account_id}")
        
        # Center - Region
        canvas_obj.drawString(280, 42, f"Region: {region}")
        
        # Right side - Scan date
        canvas_obj.drawString(420, 42, f"Scan Date: {scan_date}")
        
        # Bottom left - Branding
        canvas_obj.setFont(default_font, 8)
        canvas_obj.setFillColor(colors.HexColor('#757575'))
        canvas_obj.drawString(50, 12, "AWS Security Audit Tool")
        
        # Bottom right - Confidentiality
        canvas_obj.setFont(default_font_bold, 9)
        canvas_obj.setFillColor(colors.HexColor('#d32f2f'))
        canvas_obj.drawRightString(width - 50, 22, "⚠ CONFIDENTIAL")
        
        canvas_obj.setFont(default_font, 8)
        canvas_obj.setFillColor(colors.HexColor('#757575'))
        canvas_obj.drawRightString(width - 50, 12, "For Customer Use Only")
        
    def draw_account_details(canvas_obj, y_pos, acc_id, reg, scan_dt, risk_sc, risk_lv, risk_clr, crit_count):
        """Draw account details with professional blue/white design"""
        box_height = 95
        box_y = y_pos - box_height
        
        # Box background - Light blue
        canvas_obj.setFillColor(colors.HexColor('#E3F2FD'))
        canvas_obj.setStrokeColor(colors.HexColor('#1565C0'))
        canvas_obj.setLineWidth(2)
        canvas_obj.roundRect(50, box_y, width - 100, box_height, 10, fill=True, stroke=True)
        
        # Title
        canvas_obj.setFillColor(colors.HexColor('#0D47A1'))
        canvas_obj.setFont(default_font_bold, 18)
        title_text = "Account Information"
        icon = "📋 "
        canvas_obj.drawString(70, box_y + 70, f"{icon}{title_text}")
        
        # Details
        canvas_obj.setFont(default_font, 11)
        canvas_obj.setFillColor(colors.HexColor('#424242'))
        account_label = "Account ID"
        region_label = "Region"
        scan_label = "Scan Date"
        canvas_obj.drawString(70, box_y + 50, f"{account_label}: {acc_id}")
        canvas_obj.drawString(70, box_y + 35, f"{region_label}: {reg}")
        canvas_obj.drawString(70, box_y + 20, f"{scan_label}: {scan_dt}")
        
        # Compliance Status
        canvas_obj.setFont(default_font_bold, 12)
        canvas_obj.setFillColor(colors.HexColor('#424242'))
        compliance_label = "Compliance Status"
        canvas_obj.drawString(400, box_y + 45, f"{compliance_label}:")
        canvas_obj.setFont(default_font_bold, 11)
        if crit_count > 0:
            canvas_obj.setFillColor(colors.HexColor('#d32f2f'))
            non_compliant = "Non-Compliant"
            canvas_obj.drawString(400, box_y + 28, f"⚠ {non_compliant}")
        else:
            canvas_obj.setFillColor(colors.HexColor('#388e3c'))
            compliant = "Compliant"
            canvas_obj.drawString(400, box_y + 28, f"✓ {compliant}")
        
        return box_y - 20
    
    def draw_executive_summary(canvas_obj, y_pos, scored_report, critical, high, medium, low):
        """Draw executive summary with professional blue/white design"""
        box_height = 95
        box_y = y_pos - box_height
        
        # Box background - White with blue border
        canvas_obj.setFillColor(colors.white)
        canvas_obj.setStrokeColor(colors.HexColor('#1565C0'))
        canvas_obj.setLineWidth(2)
        canvas_obj.roundRect(50, box_y, width - 100, box_height, 10, fill=True, stroke=True)
        
        # Title
        canvas_obj.setFillColor(colors.HexColor('#0D47A1'))
        canvas_obj.setFont(default_font_bold, 17)
        title_text = "Executive Summary"
        icon = "📝 "
        canvas_obj.drawString(70, box_y + 70, f"{icon}{title_text}")
        
        # Summary text
        canvas_obj.setFont(default_font, 10)
        canvas_obj.setFillColor(colors.HexColor('#424242'))
        
        # Generate summary based on findings
        if critical > 0:
            summary_line1 = f"This security audit identified {critical} CRITICAL issues requiring immediate attention."
            summary_line2 = f"These vulnerabilities pose significant security risks and should be addressed within 24-48 hours."
        elif high > 0:
            summary_line1 = f"This security audit identified {high} HIGH priority issues requiring prompt action."
            summary_line2 = f"These issues should be addressed within 1 week to maintain security posture."
        elif medium > 0:
            summary_line1 = f"This security audit identified {medium} MEDIUM priority issues."
            summary_line2 = f"These items should be addressed in the next maintenance window (within 2 weeks)."
        else:
            summary_line1 = f"This security audit identified {low} LOW priority items for review."
            summary_line2 = f"Your AWS environment shows good security posture. Address items during regular reviews."
        
        canvas_obj.drawString(70, box_y + 48, summary_line1)
        canvas_obj.drawString(70, box_y + 33, summary_line2)
        
        # Additional context
        canvas_obj.setFont(default_font, 9)
        canvas_obj.setFillColor(colors.HexColor('#666666'))
        total_checks = len(scored_report)
        canvas_obj.drawString(70, box_y + 15, f"Total Security Checks Performed: {total_checks} | Detailed recommendations with AWS documentation links provided.")
        
        return box_y - 20
    
    def draw_summary_box(canvas_obj, y_pos, total_findings, critical, high, medium, low):
        """Draw enhanced summary statistics box with professional blue/white design"""
        box_height = 115
        box_y = y_pos - box_height
        
        # Main box background - White with blue border
        canvas_obj.setFillColor(colors.white)
        canvas_obj.setStrokeColor(colors.HexColor('#1565C0'))
        canvas_obj.setLineWidth(2)
        canvas_obj.roundRect(50, box_y, width - 100, box_height, 10, fill=True, stroke=True)
        
        # Title with icon
        canvas_obj.setFillColor(colors.HexColor('#0D47A1'))
        canvas_obj.setFont(default_font_bold, 18)
        title_text = "Findings Breakdown"
        icon = "📊 "
        canvas_obj.drawString(70, box_y + 90, f"{icon}{title_text}")
        
        # Security Status - large and prominent
        canvas_obj.setFont(default_font_bold, 18)
        if critical > 0:
            canvas_obj.setFillColor(colors.HexColor('#d32f2f'))
            status_text = "CRITICAL ISSUES FOUND"
        elif high > 0:
            canvas_obj.setFillColor(colors.HexColor('#f57c00'))
            status_text = "HIGH PRIORITY ISSUES"
        elif medium > 0:
            canvas_obj.setFillColor(colors.HexColor('#fbc02d'))
            status_text = "MEDIUM PRIORITY ISSUES"
        else:
            canvas_obj.setFillColor(colors.HexColor('#388e3c'))
            status_text = "LOW PRIORITY ITEMS"
        
        canvas_obj.drawCentredString(width/2, box_y + 62, status_text)
        
        # Severity breakdown with colored boxes
        y_offset = box_y + 25
        box_width = 105
        box_spacing = 12
        start_x = 70
        
        severities = [
            (critical, "Critical", severity_colors[3]),
            (high, "High", severity_colors[2]),
            (medium, "Medium", severity_colors[1]),
            (low, "Low", severity_colors[0])
        ]
        
        for i, (count, label, color) in enumerate(severities):
            x = start_x + i * (box_width + box_spacing)
            
            # Draw colored box
            canvas_obj.setFillColor(color)
            canvas_obj.roundRect(x, y_offset - 5, box_width, 24, 4, fill=True, stroke=False)
            
            # Draw count and label
            canvas_obj.setFillColor(colors.white)
            canvas_obj.setFont(default_font_bold, 11)
            canvas_obj.drawCentredString(x + box_width/2, y_offset + 3, f"{count} {label}")
        
        return box_y - 20
    
    def draw_security_quote(canvas_obj, y_pos):
        """Draw an inspirational security quote box"""
        quote_data = get_security_quote()
        
        box_height = 110
        box_y = y_pos - box_height
        
        # Ensure we don't go below footer
        if box_y < 100:
            return
        
        # Box background - Light blue with blue border
        canvas_obj.setFillColor(colors.HexColor('#E3F2FD'))
        canvas_obj.setStrokeColor(colors.HexColor('#1565C0'))
        canvas_obj.setLineWidth(2)
        canvas_obj.roundRect(50, box_y, width - 100, box_height, 10, fill=True, stroke=True)
        
        # Quote icon
        canvas_obj.setFillColor(colors.HexColor('#1565C0'))
        canvas_obj.setFont("Helvetica-Bold", 32)
        canvas_obj.drawString(70, box_y + 70, '"')
        
        # Title
        canvas_obj.setFillColor(colors.HexColor('#0D47A1'))
        canvas_obj.setFont("Helvetica-Bold", 16)
        canvas_obj.drawString(100, box_y + 80, "Security Wisdom")
        
        # Quote text - wrap if needed
        canvas_obj.setFont("Helvetica-Oblique", 11)
        canvas_obj.setFillColor(colors.HexColor('#424242'))
        
        quote_text = quote_data['text']
        max_width = width - 180
        
        # Simple text wrapping
        words = quote_text.split()
        lines = []
        current_line = []
        
        for word in words:
            test_line = ' '.join(current_line + [word])
            if canvas_obj.stringWidth(test_line, "Helvetica-Oblique", 11) <= max_width:
                current_line.append(word)
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
        
        if current_line:
            lines.append(' '.join(current_line))
        
        # Draw quote lines
        quote_y = box_y + 55
        for line in lines[:3]:  # Max 3 lines
            canvas_obj.drawString(80, quote_y, line)
            quote_y -= 15
        
        # Author
        canvas_obj.setFont("Helvetica-Bold", 10)
        canvas_obj.setFillColor(colors.HexColor('#1565C0'))
        canvas_obj.drawRightString(width - 70, box_y + 15, f"— {quote_data['author']}")
        
        # Closing quote icon
        canvas_obj.setFont("Helvetica-Bold", 32)
        canvas_obj.drawRightString(width - 70, box_y + 70, '"')
    
    def draw_comparison_section(canvas_obj, y_pos, comparison_data):
        """Draw comparison with previous month's audit"""
        if not comparison_data:
            return y_pos
        
        # Title
        canvas_obj.setFillColor(colors.HexColor('#0D47A1'))
        canvas_obj.setFont("Helvetica-Bold", 20)
        canvas_obj.drawString(50, y_pos, "📈 Trend Analysis - Comparison with Previous Audit")
        y_pos -= 30
        
        # Previous scan date
        canvas_obj.setFont("Helvetica", 10)
        canvas_obj.setFillColor(colors.HexColor('#666666'))
        prev_date = comparison_data.get('previous_date', 'Unknown')
        if prev_date != 'Unknown':
            try:
                prev_date = datetime.fromisoformat(prev_date.replace('Z', '+00:00')).strftime('%Y-%m-%d')
            except:
                pass
        canvas_obj.drawString(50, y_pos, f"Comparing with audit from: {prev_date}")
        y_pos -= 30
        
        # Overall trend box
        totals_change = comparison_data.get('totals_change', {})
        total_change = totals_change.get('total', {})
        
        box_height = 80
        box_y = y_pos - box_height
        
        # Determine trend color
        change_value = total_change.get('change', 0)
        if change_value < 0:
            box_color = colors.HexColor('#E8F5E9')
            border_color = colors.HexColor('#4CAF50')
            trend_color = colors.HexColor('#2E7D32')
            trend_icon = "📉"
            trend_text = "IMPROVEMENT"
        elif change_value > 0:
            box_color = colors.HexColor('#FFEBEE')
            border_color = colors.HexColor('#F44336')
            trend_color = colors.HexColor('#C62828')
            trend_icon = "📈"
            trend_text = "REGRESSION"
        else:
            box_color = colors.HexColor('#FFF9C4')
            border_color = colors.HexColor('#FBC02D')
            trend_color = colors.HexColor('#F57F17')
            trend_icon = "➡"
            trend_text = "NO CHANGE"
        
        canvas_obj.setFillColor(box_color)
        canvas_obj.setStrokeColor(border_color)
        canvas_obj.setLineWidth(2)
        canvas_obj.roundRect(50, box_y, width - 100, box_height, 10, fill=True, stroke=True)
        
        # Trend icon and text
        canvas_obj.setFont("Helvetica-Bold", 24)
        canvas_obj.setFillColor(trend_color)
        canvas_obj.drawString(70, box_y + 50, trend_icon)
        
        canvas_obj.setFont("Helvetica-Bold", 18)
        canvas_obj.drawString(110, box_y + 52, trend_text)
        
        # Change details
        canvas_obj.setFont("Helvetica", 11)
        canvas_obj.setFillColor(colors.HexColor('#424242'))
        canvas_obj.drawString(70, box_y + 30, f"Total Findings: {total_change.get('previous', 0)} → {total_change.get('current', 0)} ({change_value:+d})")
        
        # Severity breakdown
        crit_change = totals_change.get('critical', {}).get('change', 0)
        high_change = totals_change.get('high', {}).get('change', 0)
        med_change = totals_change.get('medium', {}).get('change', 0)
        
        canvas_obj.setFont("Helvetica", 10)
        canvas_obj.drawString(70, box_y + 15, f"Critical: {crit_change:+d}  |  High: {high_change:+d}  |  Medium: {med_change:+d}")
        
        y_pos = box_y - 25
        
        # Improvements and Regressions side by side
        improvements = comparison_data.get('improvements', [])
        regressions = comparison_data.get('regressions', [])
        
        if improvements or regressions:
            col_width = (width - 120) / 2
            
            # Improvements column
            if improvements:
                canvas_obj.setFillColor(colors.HexColor('#2E7D32'))
                canvas_obj.setFont("Helvetica-Bold", 14)
                canvas_obj.drawString(50, y_pos, f"✓ Improvements ({len(improvements)})")
                y_pos -= 18
                
                canvas_obj.setFont("Helvetica", 9)
                canvas_obj.setFillColor(colors.HexColor('#424242'))
                for imp in improvements[:5]:
                    check_name = imp['check'].replace('_', ' ').title()
                    canvas_obj.drawString(55, y_pos, f"• {check_name}: {imp['previous']} → {imp['current']} (-{imp['change']})")
                    y_pos -= 12
                
                if len(improvements) > 5:
                    canvas_obj.setFillColor(colors.HexColor('#666666'))
                    canvas_obj.drawString(55, y_pos, f"... and {len(improvements) - 5} more")
                    y_pos -= 12
            
            # Reset y_pos for regressions column
            y_pos_reg = y_pos + (len(improvements[:5]) * 12) + 30 if improvements else y_pos
            
            # Regressions column
            if regressions:
                canvas_obj.setFillColor(colors.HexColor('#C62828'))
                canvas_obj.setFont("Helvetica-Bold", 14)
                canvas_obj.drawString(width/2 + 10, y_pos_reg, f"⚠ Regressions ({len(regressions)})")
                y_pos_reg -= 18
                
                canvas_obj.setFont("Helvetica", 9)
                canvas_obj.setFillColor(colors.HexColor('#424242'))
                for reg in regressions[:5]:
                    check_name = reg['check'].replace('_', ' ').title()
                    canvas_obj.drawString(width/2 + 15, y_pos_reg, f"• {check_name}: {reg['previous']} → {reg['current']} (+{reg['change']})")
                    y_pos_reg -= 12
                
                if len(regressions) > 5:
                    canvas_obj.setFillColor(colors.HexColor('#666666'))
                    canvas_obj.drawString(width/2 + 15, y_pos_reg, f"... and {len(regressions) - 5} more")
            
            y_pos = min(y_pos, y_pos_reg) - 10
        
        return y_pos
    
    # Page 1 - Start
    page_num = 1
    draw_header(c, page_num)
    y = height - 110
    
    # Draw account details box
    y = draw_account_details(c, y, account_id, region, scan_date, risk_score, risk_level, risk_color, critical_findings)
    
    # Draw executive summary
    y = draw_executive_summary(c, y, scored_report, critical_findings, high_findings, medium_findings, low_findings)
    
    # Draw summary box
    y = draw_summary_box(c, y, total_findings, critical_findings, high_findings, medium_findings, low_findings)
    
    # Draw compliance scores if frameworks selected
    if compliance_frameworks and len(compliance_frameworks) > 0:
        y -= 35
        # Calculate compliance scores
        compliance_scores = {}
        for framework in compliance_frameworks:
            total_checks = 0
            failed_checks = 0
            for entry in scored_report:
                check_id = entry['check']
                if framework in COMPLIANCE_MAPPING.get(check_id, []):
                    total_checks += 1
                    if entry['count'] > 0:
                        failed_checks += 1
            
            passed_checks = total_checks - failed_checks
            score = (passed_checks / total_checks * 100) if total_checks > 0 else 100
            compliance_scores[framework] = {
                'score': score,
                'total': total_checks,
                'passed': passed_checks,
                'failed': failed_checks
            }
        
        # Draw compliance section
        c.setFillColor(colors.HexColor('#0D47A1'))
        c.setFont(default_font_bold, 20)
        compliance_title = "Compliance Frameworks"
        icon = "🏥 "
        c.drawString(50, y, f"{icon}{compliance_title}")
        y -= 30
        
        # Draw each framework score
        for framework, data in compliance_scores.items():
            if y < 150:
                draw_footer(c)
                c.showPage()
                page_num += 1
                draw_header(c, page_num)
                y = height - 110
            
            # Framework box
            box_height = 60
            box_y = y - box_height
            
            # Color based on score
            if data['score'] >= 90:
                box_color = colors.HexColor('#E8F5E9')
                border_color = colors.HexColor('#4CAF50')
                score_color = colors.HexColor('#2E7D32')
            elif data['score'] >= 70:
                box_color = colors.HexColor('#FFF9C4')
                border_color = colors.HexColor('#FBC02D')
                score_color = colors.HexColor('#F57F17')
            else:
                box_color = colors.HexColor('#FFEBEE')
                border_color = colors.HexColor('#F44336')
                score_color = colors.HexColor('#C62828')
            
            c.setFillColor(box_color)
            c.setStrokeColor(border_color)
            c.setLineWidth(2)
            c.roundRect(50, box_y, width - 100, box_height, 8, fill=True, stroke=True)
            
            # Framework name
            c.setFillColor(colors.HexColor('#0D47A1'))
            c.setFont(default_font_bold, 14)
            c.drawString(70, box_y + 40, framework)
            
            # Score
            c.setFillColor(score_color)
            c.setFont(default_font_bold, 24)
            c.drawString(70, box_y + 15, f"{data['score']:.1f}%")
            
            # Details
            c.setFillColor(colors.HexColor('#424242'))
            c.setFont(default_font, 10)
            checks_passed_label = "checks passed"
            c.drawString(150, box_y + 20, f"{data['passed']}/{data['total']} {checks_passed_label}")
            
            # Status badge
            if data['score'] >= 90:
                c.setFillColor(colors.HexColor('#4CAF50'))
                compliant_text = "Compliant"
                c.drawRightString(width - 70, box_y + 30, f"✓ {compliant_text.upper()}")
            else:
                c.setFillColor(colors.HexColor('#F44336'))
                non_compliant_text = "Non-Compliant"
                c.drawRightString(width - 70, box_y + 30, f"✗ {non_compliant_text.upper()}")
            
            y = box_y - 15
        
        y -= 20
    
    # Findings section
    y -= 35
    c.setFillColor(colors.HexColor('#0D47A1'))
    c.setFont(default_font_bold, 20)
    detailed_findings_text = "Detailed Findings"
    c.drawString(50, y, detailed_findings_text)
    y -= 40
    
    # Draw each finding
    for entry in scored_report:
        severity = entry['severity']
        sev_text = severity_names.get(severity, "UNKNOWN")
        sev_color = severity_colors.get(severity, colors.black)
        
        # Check if we need a new page
        if y < 130:
            draw_footer(c)
            c.showPage()
            page_num += 1
            draw_header(c, page_num)
            y = height - 110
        
        # Draw severity badge
        badge_width = 75
        badge_height = 18
        c.setFillColor(sev_color)
        c.roundRect(50, y - badge_height, badge_width, badge_height, 5, fill=True, stroke=False)
        
        c.setFillColor(colors.white)
        c.setFont(default_font_bold, 9)
        c.drawCentredString(50 + badge_width/2, y - 13, sev_text)
        
        # Draw finding title (without count) - make it readable
        c.setFillColor(colors.HexColor('#0D47A1'))
        c.setFont(default_font_bold, 16)
        
        # Convert check name to readable format
        readable_title = entry['check'].replace('_', ' ').title()
        
        # Special formatting for common abbreviations
        readable_title = readable_title.replace('Ec2', 'EC2')
        readable_title = readable_title.replace('S3', 'S3')
        readable_title = readable_title.replace('Iam', 'IAM')
        readable_title = readable_title.replace('Rds', 'RDS')
        readable_title = readable_title.replace('Ebs', 'EBS')
        readable_title = readable_title.replace('Ecs', 'ECS')
        readable_title = readable_title.replace('Api', 'API')
        readable_title = readable_title.replace('Gw', 'Gateway')
        readable_title = readable_title.replace('Kms', 'KMS')
        readable_title = readable_title.replace('Sg', 'Security Group')
        readable_title = readable_title.replace('Imdsv2', 'IMDSv2')
        readable_title = readable_title.replace('0 0 0 0', 'Open to Internet (0.0.0.0/0)')
        
        c.drawString(135, y - 16, readable_title)
        
        # Draw count separately in smaller text
        c.setFont(default_font, 13)
        c.setFillColor(colors.HexColor('#757575'))
        c.drawString(135 + c.stringWidth(readable_title, default_font_bold, 16) + 12, y - 16, f"({entry['count']})")
        c.setFillColor(colors.black)
        
        y -= 35
        
        # Draw items with enhanced formatting
        c.setFont(default_font, 10)
        
        # Show all items for IAM roles, limited for others
        max_items = len(entry['items']) if 'IAM' in entry['check'] and 'ROLE' in entry['check'] else 15
        
        for item in entry['items'][:max_items]:
            if y < 110:
                draw_footer(c)
                c.showPage()
                page_num += 1
                draw_header(c, page_num)
                y = height - 110
            
            # Format item text based on type
            if isinstance(item, dict):
                # Different formatting for different check types
                if 'UserName' in item and 'DaysInactive' in item:
                    # IAM User
                    c.setFillColor(colors.HexColor('#d32f2f') if item['DaysInactive'] > 180 else colors.HexColor('#f57c00'))
                    item_text = f"• {item['UserName']} - {item['Status']} ({item['DaysInactive']} days)"
                elif 'UserName' in item and 'AccessKeyId' in item:
                    # Access Key
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• {item['UserName']} - Key: ...{item['AccessKeyId']} - {item['Status']} ({item['Age']})"
                elif 'RoleName' in item and 'DaysOld' in item:
                    # IAM Role
                    days_since_use = item.get('DaysSinceUse', item.get('DaysOld', 0))
                    c.setFillColor(colors.HexColor('#f57c00') if days_since_use > 180 else colors.HexColor('#424242'))
                    if 'Policies' in item:
                        # All roles view
                        item_text = f"• {item['RoleName']} - {item['Status']} ({item['Policies']} policies, {item['DaysOld']} days old)"
                    else:
                        # Unused roles view
                        item_text = f"• {item['RoleName']} - {item['Status']} ({item['DaysOld']} days old)"
                elif 'BucketName' in item:
                    # S3 Bucket (public or policy issues)
                    c.setFillColor(colors.HexColor('#d32f2f'))
                    
                    if 'Risk' in item:
                        # Bucket policy issue
                        item_text = f"• {item['BucketName']} | Risk: {item.get('Risk', 'Unknown')}"
                        aws_url = 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html'
                    else:
                        # Public bucket (simplified - CloudFront buckets already excluded)
                        item_text = f"• {item['BucketName']}"
                        aws_url = 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html'
                    c.drawString(70, y, item_text)
                    y -= 15
                    continue
                elif 'VolumeId' in item:
                    # EBS Volume
                    c.setFillColor(colors.HexColor('#424242'))
                    item_text = f"• {item['VolumeId']} - {item['Size']} ({item.get('Type', 'unknown')}, {item.get('State', 'unknown')})"
                elif 'DBInstanceIdentifier' in item:
                    # RDS Instance
                    c.setFillColor(colors.HexColor('#424242'))
                    item_text = f"• {item['DBInstanceIdentifier']} - {item.get('Engine', 'unknown')} ({item.get('Size', 'N/A')}, {item.get('Status', 'unknown')})"
                elif 'GroupId' in item:
                    # Security Group with full details
                    c.setFillColor(colors.HexColor('#d32f2f'))
                    item_text = f"• {item['GroupId']} - {item.get('GroupName', 'N/A')} | Port: {item.get('Port', 'All')} | Protocol: {item.get('Protocol', 'All')} | VPC: {item.get('VpcId', 'N/A')}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    
                    # Add remediation command
                    if 'Remediation' in item and y > 120:
                        c.setFont("Helvetica-Oblique", 9)
                        c.setFillColor(colors.HexColor('#1565C0'))
                        c.drawString(90, y, f"Fix: {item['Remediation'][:85]}")
                        y -= 13
                        
                        # Add AWS documentation URL
                        c.setFont("Helvetica", 8)
                        c.setFillColor(colors.HexColor('#1565C0'))
                        aws_url = get_aws_documentation_url(entry['check'])
                        c.drawString(90, y, f"📚 AWS Docs: {aws_url}")
                        y -= 13
                        
                        c.setFont("Helvetica", 10)
                        c.setFillColor(colors.HexColor('#424242'))
                    continue
                elif 'Name' in item and 'DaysOld' in item and 'Type' in item:
                    # Parameter Store item
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• {item['Name']} | Type: {item.get('Type', 'Unknown')} | Last Modified: {item.get('LastModified', 'Unknown')} ({item['DaysOld']} days ago)"
                    c.drawString(70, y, item_text)
                    y -= 15
                    
                    # Add remediation
                    if 'Recommendation' in item and y > 120:
                        c.setFont("Helvetica-Oblique", 9)
                        c.setFillColor(colors.HexColor('#1565C0'))
                        c.drawString(90, y, f"Fix: {item['Recommendation'][:85]}")
                        y -= 13
                        
                        # Add AWS documentation URL
                        c.setFont("Helvetica", 8)
                        c.setFillColor(colors.HexColor('#1565C0'))
                        aws_url = get_aws_documentation_url(entry['check'])
                        c.drawString(90, y, f"📚 AWS Docs: {aws_url}")
                        y -= 13
                        
                        c.setFont("Helvetica", 10)
                        c.setFillColor(colors.HexColor('#424242'))
                    continue
                elif 'VpcId' in item:
                    # VPC Flow Logs
                    c.setFillColor(colors.HexColor('#f57c00'))
                    default_text = " (Default VPC)" if item.get('IsDefault') else ""
                    item_text = f"• VPC: {item['VpcId']}{default_text} | CIDR: {item.get('CidrBlock', 'N/A')}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    continue
                elif 'FunctionName' in item and 'Runtime' in item:
                    # Lambda Function
                    c.setFillColor(colors.HexColor('#d32f2f'))
                    item_text = f"• Function: {item['FunctionName']} | Runtime: {item.get('Runtime', 'N/A')} | Modified: {item.get('LastModified', 'N/A')}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    continue
                elif 'TopicArn' in item and 'FullArn' in item:
                    # SNS Topic
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• SNS Topic: {item['TopicArn']}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    continue
                elif 'QueueName' in item and 'QueueUrl' in item:
                    # SQS Queue
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• SQS Queue: {item['QueueName']}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    continue
                elif 'TrailName' in item and 'Issues' in item:
                    # CloudTrail
                    c.setFillColor(colors.HexColor('#d32f2f'))
                    logging_status = "✓ Enabled" if item.get('IsLogging') else "✗ Disabled"
                    encryption_status = "✓ Encrypted" if item.get('Encrypted') else "✗ Not Encrypted"
                    validation_status = "✓ Validated" if item.get('LogValidation') else "✗ No Validation"
                    item_text = f"• Trail: {item['TrailName']} | Logging: {logging_status} | Encryption: {encryption_status} | Validation: {validation_status}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    
                    # Show issues on next line
                    if y > 120:
                        c.setFont("Helvetica-Oblique", 9)
                        c.setFillColor(colors.HexColor('#d32f2f'))
                        c.drawString(90, y, f"Issues: {item['Issues']}")
                        y -= 13
                        c.setFont("Helvetica", 10)
                        c.setFillColor(colors.HexColor('#424242'))
                    continue
                elif 'ImageId' in item and 'UnencryptedVolumes' in item:
                    # AMI
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• AMI: {item['ImageId']} | Name: {item.get('Name', 'N/A')} | Created: {item.get('CreationDate', 'N/A')} | State: {item.get('State', 'N/A')}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    
                    # Show unencrypted volumes on next line
                    if y > 120:
                        c.setFont("Helvetica-Oblique", 9)
                        c.setFillColor(colors.HexColor('#f57c00'))
                        c.drawString(90, y, f"Unencrypted Volumes: {item['UnencryptedVolumes']}")
                        y -= 13
                        c.setFont("Helvetica", 10)
                        c.setFillColor(colors.HexColor('#424242'))
                    continue
                elif 'LoadBalancerName' in item and 'Type' in item:
                    # ELB
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• Load Balancer: {item['LoadBalancerName']} | Type: {item.get('Type', 'N/A')} | Scheme: {item.get('Scheme', 'N/A')}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    continue
                elif 'Issue' in item and 'Risk' in item:
                    # Root MFA
                    c.setFillColor(colors.HexColor('#d32f2f'))
                    item_text = f"• {item['Issue']} | Risk: {item.get('Risk', 'Unknown')}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    continue
                elif 'SecretName' in item and 'EncryptionType' in item:
                    # Secrets Manager - Without Customer-Managed KMS
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• Secret: {item['SecretName']} | Encryption: {item.get('EncryptionType', 'Unknown')} | Created: {item.get('CreatedDate', 'Unknown')}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    
                    # Add explanation and remediation
                    if y > 120:
                        c.setFont("Helvetica-Oblique", 9)
                        c.setFillColor(colors.HexColor('#666666'))
                        c.drawString(90, y, "Note: Secret is encrypted but using AWS-managed key instead of customer-managed KMS key")
                        y -= 13
                        
                        c.setFillColor(colors.HexColor('#1565C0'))
                        c.drawString(90, y, f"Fix: {item.get('Recommendation', 'Use customer-managed KMS key')}")
                        y -= 13
                        
                        # Add AWS documentation URL
                        c.setFont("Helvetica", 8)
                        c.drawString(90, y, "📚 AWS Docs: https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html")
                        y -= 13
                        
                        c.setFont("Helvetica", 10)
                        c.setFillColor(colors.HexColor('#424242'))
                    continue
                elif 'ParameterName' in item and 'Type' in item and 'Tier' in item:
                    # SSM Parameter Store - Plaintext Parameters
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• Parameter: {item['ParameterName']} | Type: {item.get('Type', 'Unknown')} | Tier: {item.get('Tier', 'Standard')} | Modified: {item.get('LastModified', 'Unknown')}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    
                    # Add explanation and remediation
                    if y > 120:
                        c.setFont("Helvetica-Oblique", 9)
                        c.setFillColor(colors.HexColor('#666666'))
                        c.drawString(90, y, f"Note: Parameter type '{item.get('Type')}' stores data in plaintext (not encrypted)")
                        y -= 13
                        
                        c.setFillColor(colors.HexColor('#1565C0'))
                        c.drawString(90, y, f"Fix: {item.get('Recommendation', 'Change to SecureString type')}")
                        y -= 13
                        
                        # Add AWS documentation URL
                        c.setFont("Helvetica", 8)
                        c.drawString(90, y, "📚 AWS Docs: https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-securestring.html")
                        y -= 13
                        
                        c.setFont("Helvetica", 10)
                        c.setFillColor(colors.HexColor('#424242'))
                    continue
                elif 'TableName' in item and 'TableStatus' in item:
                    # DynamoDB Table
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• Table: {item['TableName']} | Status: {item.get('TableStatus', 'unknown')} | Items: {item.get('ItemCount', 0):,} | Size: {item.get('TableSizeBytes', '0 MB')}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    
                    # Add explanation
                    if y > 120:
                        c.setFont("Helvetica-Oblique", 9)
                        c.setFillColor(colors.HexColor('#666666'))
                        c.drawString(90, y, "Note: Table does not have encryption at rest enabled")
                        y -= 13
                        
                        c.setFillColor(colors.HexColor('#1565C0'))
                        c.drawString(90, y, "Fix: Enable encryption at rest with AWS-managed or customer-managed KMS key")
                        y -= 13
                        
                        # Add AWS documentation URL
                        c.setFont("Helvetica", 8)
                        c.drawString(90, y, "📚 AWS Docs: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html")
                        y -= 13
                        
                        c.setFont("Helvetica", 10)
                        c.setFillColor(colors.HexColor('#424242'))
                    continue
                elif 'SnapshotId' in item and 'VolumeId' in item:
                    # EBS Snapshot
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• Snapshot: {item['SnapshotId']} | Volume: {item.get('VolumeId', 'N/A')} | Size: {item.get('Size', 'N/A')} | Created: {item.get('StartTime', 'Unknown')}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    continue
                elif 'ClusterIdentifier' in item and 'Engine' in item:
                    # Aurora Cluster
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• Cluster: {item['ClusterIdentifier']} | Engine: {item.get('Engine', 'unknown')} | Status: {item.get('Status', 'unknown')} | Members: {item.get('Members', 0)}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    continue
                elif 'VaultName' in item and 'VaultArn' in item:
                    # Backup Vault
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• Vault: {item['VaultName']}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    continue
                elif 'KeyName' in item and 'KeyPairId' in item:
                    # EC2 Key Pair
                    c.setFillColor(colors.HexColor('#424242'))
                    item_text = f"• Key Pair: {item['KeyName']} | ID: {item.get('KeyPairId', 'N/A')} | Fingerprint: {item.get('Fingerprint', 'N/A')}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    continue
                elif 'InstanceId' in item and 'PublicIP' in item:
                    # EC2 with Public IP
                    c.setFillColor(colors.HexColor('#f57c00'))
                    item_text = f"• Instance: {item['InstanceId']} | Public IP: {item.get('PublicIP', 'N/A')} | Type: {item.get('InstanceType', 'N/A')} | Subnet: {item.get('SubnetId', 'N/A')}"
                    c.drawString(70, y, item_text)
                    y -= 15
                    continue
                else:
                    c.setFillColor(colors.HexColor('#424242'))
                    item_text = f"• {str(item)[:100]}"
            else:
                c.setFillColor(colors.HexColor('#424242'))
                item_text = f"• {str(item)[:100]}"
            
            c.drawString(70, y, item_text)
            y -= 15
            
            # Add remediation and URL for simple string items (Aurora, KMS, Secrets, etc.)
            if not isinstance(item, dict) and y > 120:
                c.setFont("Helvetica-Oblique", 9)
                c.setFillColor(colors.HexColor('#1565C0'))
                recommendation = get_recommendation(entry['check'])
                c.drawString(90, y, f"Fix: {recommendation[:85]}")
                y -= 13
                
                # Add AWS documentation URL
                c.setFont("Helvetica", 8)
                c.setFillColor(colors.HexColor('#1565C0'))
                aws_url = get_aws_documentation_url(entry['check'])
                c.drawString(90, y, f"📚 AWS Docs: {aws_url}")
                y -= 13
                
                c.setFont("Helvetica", 10)
                c.setFillColor(colors.HexColor('#424242'))
        
        # Show "and X more" if there are more items (skip for IAM roles)
        if entry['count'] > max_items:
            c.setFillColor(colors.HexColor('#757575'))
            c.setFont("Helvetica-Oblique", 10)
            c.drawString(70, y, f"... and {entry['count'] - max_items} more")
            y -= 16
        
        # Add detailed recommendation box for ALL findings
        # Force page break if not enough space
        if y < 180:
            draw_footer(c)
            c.showPage()
            page_num += 1
            draw_header(c, page_num)
            y = height - 110
        
        # Get comprehensive finding details
        finding_details = get_finding_details(entry['check'])
        
        # Color-code recommendation box by severity
        if severity == 3:
            box_color = colors.HexColor('#FFEBEE')
            border_color = colors.HexColor('#d32f2f')
            title_color = colors.HexColor('#b71c1c')
            title_text = "⚠ IMMEDIATE ACTION REQUIRED"
        elif severity == 2:
            box_color = colors.HexColor('#FFF3E0')
            border_color = colors.HexColor('#f57c00')
            title_color = colors.HexColor('#e65100')
            title_text = "⚠ HIGH PRIORITY ACTION"
        elif severity == 1:
            box_color = colors.HexColor('#FFFDE7')
            border_color = colors.HexColor('#fbc02d')
            title_color = colors.HexColor('#f57f17')
            title_text = "⚡ MEDIUM PRIORITY"
        else:
            box_color = colors.HexColor('#E8F5E9')
            border_color = colors.HexColor('#8bc34a')
            title_color = colors.HexColor('#558b2f')
            title_text = "ℹ LOW PRIORITY"
        
        # Calculate box height based on solution text
        solution_lines = finding_details['solution'].split('\n')
        box_height = 95 + (len(solution_lines) * 12)
        
        c.setFillColor(box_color)
        c.setStrokeColor(border_color)
        c.setLineWidth(2)
        c.roundRect(70, y - box_height, width - 140, box_height, 8, fill=True, stroke=True)
        
        c.setFillColor(title_color)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(80, y - 18, title_text)
        
        # Draw details
        c.setFont("Helvetica-Bold", 9)
        c.setFillColor(colors.HexColor('#424242'))
        y_offset = 33
        
        c.drawString(80, y - y_offset, "Recommendation:")
        c.setFont("Helvetica", 9)
        c.drawString(180, y - y_offset, finding_details['recommendation'][:70])
        y_offset += 15
        
        c.setFont("Helvetica-Bold", 9)
        c.drawString(80, y - y_offset, "Impact:")
        c.setFont("Helvetica", 9)
        c.drawString(180, y - y_offset, finding_details['impact'][:70])
        y_offset += 15
        
        c.setFont("Helvetica-Bold", 9)
        c.drawString(80, y - y_offset, "Timeline:")
        c.setFont("Helvetica", 9)
        c.drawString(180, y - y_offset, finding_details['timeline'])
        y_offset += 15
        
        c.setFont("Helvetica-Bold", 9)
        c.drawString(80, y - y_offset, "Proposed Solution:")
        y_offset += 12
        
        # Draw solution steps
        c.setFont("Helvetica", 8)
        for line in solution_lines:
            if y_offset < box_height - 10:
                c.drawString(85, y - y_offset, line[:90])
                y_offset += 12
        
        y -= (box_height + 5)
        
        y -= 30  # Space between findings
    
    # Add final page with comparison (if available) and security quote
    if comparison:
        if y < 400:
            draw_footer(c)
            c.showPage()
            page_num += 1
            draw_header(c, page_num)
            y = height - 110
        else:
            y -= 50
        
        # Draw comparison section
        y = draw_comparison_section(c, y, comparison)
        y -= 30
    
    # Add security quote on final page
    if y < 200:
        draw_footer(c)
        c.showPage()
        page_num += 1
        draw_header(c, page_num)
        y = height - 110
    else:
        y -= 30
    
    # Draw security quote box
    draw_security_quote(c, y)
    
    # Draw footer on last page
    draw_footer(c)
    
    c.save()
    buffer.seek(0)
    return buffer

def create_s3_bucket_if_not_exists(bucket_name, region, credentials=None):
    """Create S3 bucket if it doesn't exist in the audited account"""
    bucket_name = bucket_name.strip().lower()
    
    # Use provided credentials (from assumed role) or default credentials
    if credentials:
        s3 = boto3.client(
            's3',
            region_name=region,
            aws_access_key_id=credentials['aws_access_key_id'],
            aws_secret_access_key=credentials['aws_secret_access_key'],
            aws_session_token=credentials['aws_session_token']
        )
    else:
        s3 = boto3.client('s3', region_name=region)
    
    try:
        # Check if bucket exists
        s3.head_bucket(Bucket=bucket_name)
        logger.info(f"✅ S3 bucket '{bucket_name}' already exists")
        return True
    except:
        # Bucket doesn't exist, create it
        try:
            logger.info(f"📦 Creating S3 bucket '{bucket_name}'...")
            
            if region == 'us-east-1':
                # us-east-1 doesn't need LocationConstraint
                s3.create_bucket(Bucket=bucket_name)
            else:
                s3.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': region}
                )
            
            # Enable versioning
            s3.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            
            # Enable encryption
            s3.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [{
                        'ApplyServerSideEncryptionByDefault': {
                            'SSEAlgorithm': 'AES256'
                        }
                    }]
                }
            )
            
            # Block public access
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            logger.info(f"✅ S3 bucket '{bucket_name}' created successfully with encryption and versioning")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to create S3 bucket: {str(e)}")
            return False

def upload_pdf_to_s3(pdf_buffer, region, bucket_name, timestamp=None, prefix='aws_audit_reports', credentials=None):
    """Upload PDF report to S3 in the audited account"""
    bucket_name = bucket_name.strip().lower()
    
    # Use provided credentials (from assumed role) or default credentials
    if credentials:
        s3 = boto3.client(
            's3',
            region_name=region,
            aws_access_key_id=credentials['aws_access_key_id'],
            aws_secret_access_key=credentials['aws_secret_access_key'],
            aws_session_token=credentials['aws_session_token']
        )
    else:
        s3 = boto3.client('s3', region_name=region)
    if not timestamp:
        timestamp = utcnow().strftime('%Y%m%dT%H%M%SZ')
    object_key = f"{prefix}/{region}/aws_audit_{timestamp}.pdf"

    try:
        s3.put_object(
            Bucket=bucket_name,
            Key=object_key,
            Body=pdf_buffer.getvalue(),
            ContentType='application/pdf',
            ServerSideEncryption='AES256'
        )
        
        url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': bucket_name, 'Key': object_key},
            ExpiresIn=3600
        )
        
        logger.info(f"✅ PDF uploaded to S3: {object_key}")
        return object_key, url
        
    except Exception as e:
        logger.error(f"❌ Failed to upload PDF to S3: {str(e)}")
        raise

def list_previous_reports(bucket_name, region):
    """List previous audit reports from S3"""
    s3 = boto3.client('s3', region_name=region)
    
    try:
        response = s3.list_objects_v2(
            Bucket=bucket_name,
            Prefix=f'aws_audit_reports/{region}/'
        )
        
        if 'Contents' not in response:
            return []
        
        reports = []
        for obj in response['Contents']:
            reports.append({
                'key': obj['Key'],
                'size': obj['Size'],
                'last_modified': obj['LastModified']
            })
        
        return sorted(reports, key=lambda x: x['last_modified'], reverse=True)
        
    except Exception as e:
        logger.debug(f"Could not list previous reports: {str(e)}")
        return []

def get_previous_month_report(bucket_name, region):
    """Get the most recent audit report from previous month"""
    try:
        reports = list_previous_reports(bucket_name, region)
        
        if len(reports) < 2:
            return None
        
        # Get the second most recent report (first is current)
        # Look for reports from at least 20 days ago to ensure it's from previous period
        cutoff_date = utcnow() - timedelta(days=20)
        
        for report in reports[1:]:
            if report['last_modified'] < cutoff_date:
                return report
        
        return None
        
    except Exception as e:
        logger.debug(f"Could not get previous month report: {str(e)}")
        return None

def download_and_parse_previous_report(bucket_name, report_key, region):
    """Download previous report metadata (stored as JSON alongside PDF)"""
    s3 = boto3.client('s3', region_name=region)
    
    try:
        # Try to get JSON metadata file
        json_key = report_key.replace('.pdf', '_metadata.json')
        
        try:
            response = s3.get_object(Bucket=bucket_name, Key=json_key)
            metadata = json.loads(response['Body'].read().decode('utf-8'))
            return metadata
        except:
            # No metadata file exists
            return None
            
    except Exception as e:
        logger.debug(f"Could not download previous report metadata: {str(e)}")
        return None

def save_report_metadata(bucket_name, region, scored_report, timestamp):
    """Save audit metadata as JSON for future comparisons"""
    s3 = boto3.client('s3', region_name=region)
    
    try:
        # Create metadata summary
        metadata = {
            'timestamp': timestamp,
            'scan_date': utcnow().isoformat(),
            'region': region,
            'summary': {}
        }
        
        # Store counts by check type
        for entry in scored_report:
            metadata['summary'][entry['check']] = {
                'count': entry['count'],
                'severity': entry['severity']
            }
        
        # Calculate totals
        metadata['totals'] = {
            'critical': sum(e['count'] for e in scored_report if e['severity'] == 3),
            'high': sum(e['count'] for e in scored_report if e['severity'] == 2),
            'medium': sum(e['count'] for e in scored_report if e['severity'] == 1),
            'low': sum(e['count'] for e in scored_report if e['severity'] == 0),
            'total': sum(e['count'] for e in scored_report)
        }
        
        # Upload metadata
        json_key = f"aws_audit_reports/{region}/aws_audit_{timestamp}_metadata.json"
        s3.put_object(
            Bucket=bucket_name,
            Key=json_key,
            Body=json.dumps(metadata, indent=2),
            ContentType='application/json',
            ServerSideEncryption='AES256'
        )
        
        logger.info(f"✅ Metadata saved: {json_key}")
        return True
        
    except Exception as e:
        logger.warning(f"Could not save metadata: {str(e)}")
        return False

def compare_with_previous(current_report, previous_metadata):
    """Compare current audit with previous month's audit"""
    if not previous_metadata or 'summary' not in previous_metadata:
        return None
    
    comparison = {
        'previous_date': previous_metadata.get('scan_date', 'Unknown'),
        'improvements': [],
        'regressions': [],
        'new_issues': [],
        'resolved_issues': [],
        'totals_change': {}
    }
    
    # Get current summary
    current_summary = {}
    for entry in current_report:
        current_summary[entry['check']] = entry['count']
    
    previous_summary = previous_metadata.get('summary', {})
    
    # Compare each check
    all_checks = set(list(current_summary.keys()) + list(previous_summary.keys()))
    
    for check in all_checks:
        current_count = current_summary.get(check, 0)
        previous_count = previous_summary.get(check, {}).get('count', 0) if isinstance(previous_summary.get(check), dict) else previous_summary.get(check, 0)
        
        if current_count < previous_count:
            comparison['improvements'].append({
                'check': check,
                'previous': previous_count,
                'current': current_count,
                'change': previous_count - current_count
            })
        elif current_count > previous_count:
            comparison['regressions'].append({
                'check': check,
                'previous': previous_count,
                'current': current_count,
                'change': current_count - previous_count
            })
        
        if current_count > 0 and previous_count == 0:
            comparison['new_issues'].append(check)
        elif current_count == 0 and previous_count > 0:
            comparison['resolved_issues'].append(check)
    
    # Compare totals
    current_totals = {
        'critical': sum(e['count'] for e in current_report if e['severity'] == 3),
        'high': sum(e['count'] for e in current_report if e['severity'] == 2),
        'medium': sum(e['count'] for e in current_report if e['severity'] == 1),
        'low': sum(e['count'] for e in current_report if e['severity'] == 0),
        'total': sum(e['count'] for e in current_report)
    }
    
    previous_totals = previous_metadata.get('totals', {})
    
    for severity in ['critical', 'high', 'medium', 'low', 'total']:
        prev = previous_totals.get(severity, 0)
        curr = current_totals.get(severity, 0)
        comparison['totals_change'][severity] = {
            'previous': prev,
            'current': curr,
            'change': curr - prev,
            'percentage': ((curr - prev) / prev * 100) if prev > 0 else 0
        }
    
    return comparison

def main():
    """Main execution function"""
    print("=" * 60)
    print("AWS Security Audit Tool")
    print("=" * 60)
    
    region = input("\nEnter AWS region (e.g. us-east-1): ").strip() or 'us-east-1'
    bucket_name = input("Enter S3 bucket name for report storage (will be created if not exists): ").strip()
    
    if not bucket_name:
        # Generate default bucket name (one bucket per account)
        account_id = boto3.client('sts').get_caller_identity()['Account']
        bucket_name = f"aws-security-audit-{account_id}"
        print(f"✨ Using default bucket name: {bucket_name}")
    
    parallel = input("Run checks in parallel? (y/n, default=y): ").strip().lower() != 'n'
    
    try:
        # Create S3 bucket if it doesn't exist
        if not create_s3_bucket_if_not_exists(bucket_name, region):
            print("❌ Failed to create/access S3 bucket. Exiting.")
            return
        
        # Initialize audit
        audit = AWSecurityAudit(region)
        
        # Run audit
        logger.info("Running AWS security audit...")
        report = audit.run_audit(parallel=parallel)
        scored_report = audit.score_findings(report)
        
        # Display summary
        severity_names = {3: "Critical", 2: "High", 1: "Medium", 0: "Low"}
        print(f"\n{'=' * 60}")
        print(f"AWS Security Audit Summary - Region: {region}")
        print(f"{'=' * 60}\n")
        
        # Calculate severity counts
        critical_count = sum(entry['count'] for entry in scored_report if entry['severity'] == 3)
        high_count = sum(entry['count'] for entry in scored_report if entry['severity'] == 2)
        medium_count = sum(entry['count'] for entry in scored_report if entry['severity'] == 1)
        low_count = sum(entry['count'] for entry in scored_report if entry['severity'] == 0)
        
        print(f"Security Issues: 🔴 {critical_count} Critical | 🟠 {high_count} High | 🟡 {medium_count} Medium | 🟢 {low_count} Low\n")
        
        for entry in scored_report:
            severity_label = severity_names[entry['severity']]
            severity_icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
            icon = severity_icon.get(severity_label, '⚪')
            
            # Make console output readable too
            readable_name = entry['check'].replace('_', ' ').title()
            readable_name = readable_name.replace('Ec2', 'EC2').replace('S3', 'S3').replace('Iam', 'IAM')
            readable_name = readable_name.replace('Rds', 'RDS').replace('Ebs', 'EBS').replace('Ecs', 'ECS')
            readable_name = readable_name.replace('Api', 'API').replace('Gw', 'Gateway').replace('Kms', 'KMS')
            readable_name = readable_name.replace('Sg', 'Security Group').replace('Imdsv2', 'IMDSv2')
            readable_name = readable_name.replace('0 0 0 0', 'Open to Internet (0.0.0.0/0)')
            
            print(f"{icon} [{severity_label}] {readable_name}")
            
            # Show all IAM roles, limited for others
            max_console_items = len(entry['items']) if 'IAM' in entry['check'] and 'ROLE' in entry['check'] else 5
            
            for item in entry['items'][:max_console_items]:
                if isinstance(item, dict):
                    if 'UserName' in item and 'DaysInactive' in item:
                        print(f"  • {item['UserName']} - {item['Status']} ({item['DaysInactive']} days)")
                    elif 'UserName' in item and 'AccessKeyId' in item:
                        print(f"  • {item['UserName']} - Key: ...{item['AccessKeyId']} - {item['Status']}")
                    elif 'RoleName' in item and 'DaysOld' in item:
                        if 'Policies' in item:
                            print(f"  • {item['RoleName']} - {item['Status']} ({item['Policies']} policies)")
                        else:
                            print(f"  • {item['RoleName']} - {item['Status']} ({item['DaysOld']} days old)")
                    elif 'BucketName' in item:
                        if 'Risk' in item:
                            # Bucket policy issue
                            print(f"  • {item['BucketName']} | Risk: {item.get('Risk', 'Unknown')}")
                            aws_url = 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html'
                        else:
                            # Public bucket (simplified - CloudFront buckets already excluded)
                            print(f"  • {item['BucketName']}")
                            aws_url = 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html'
                        # Check both Recommendation and Remediation fields
                        remediation_text = item.get('Recommendation') or item.get('Remediation')
                        if remediation_text:
                            print(f"    Fix: {remediation_text[:100]}")
                            print(f"    📚 AWS Docs: {aws_url}")
                    elif 'Name' in item and 'DaysOld' in item and 'Type' in item:
                        # Parameter Store item
                        print(f"  • {item['Name']} | Type: {item.get('Type', 'Unknown')} | Last Modified: {item.get('LastModified', 'Unknown')} ({item['DaysOld']} days ago)")
                        if 'Recommendation' in item:
                            print(f"    Fix: {item['Recommendation']}")
                    elif 'VolumeId' in item:
                        print(f"  • {item['VolumeId']} - {item['Size']} ({item.get('Type', 'unknown')})")
                    elif 'DBInstanceIdentifier' in item:
                        print(f"  • {item['DBInstanceIdentifier']} - {item.get('Engine', 'unknown')} ({item.get('Size', 'N/A')})")
                    elif 'GroupId' in item:
                        print(f"  • {item['GroupId']} - {item.get('GroupName', 'N/A')} | Port: {item.get('Port', 'All')} | Protocol: {item.get('Protocol', 'All')}")
                        if 'Remediation' in item:
                            print(f"    Fix: {item['Remediation']}")
                            print(f"    📚 AWS Docs: {get_aws_documentation_url(entry['check'])}")
                    else:
                        print(f"  • {str(item)[:80]}")
                else:
                    # Simple string items - show recommendation and URL
                    print(f"  • {str(item)[:80]}")
                    print(f"    Fix: {get_recommendation(entry['check'])}")
                    print(f"    📚 AWS Docs: {get_aws_documentation_url(entry['check'])}")
            
            if entry['count'] > max_console_items:
                print(f"  ... and {entry['count'] - max_console_items} more")
            print()
        
        # Check for previous month's report for comparison
        logger.info("Checking for previous audit reports...")
        comparison = None
        prev_report = get_previous_month_report(bucket_name, region)
        if prev_report:
            logger.info(f"Found previous report from {prev_report['last_modified'].strftime('%Y-%m-%d')}")
            prev_metadata = download_and_parse_previous_report(bucket_name, prev_report['key'], region)
            if prev_metadata:
                comparison = compare_with_previous(scored_report, prev_metadata)
                logger.info("✅ Comparison with previous audit completed")
        
        # Generate PDF with comparison
        logger.info("Generating PDF report...")
        pdf_buffer = create_pdf_report(scored_report, region, comparison)
        
        # Upload to S3
        logger.info("Uploading PDF report to S3...")
        timestamp = utcnow().strftime('%Y%m%dT%H%M%SZ')
        object_key, presigned_url = upload_pdf_to_s3(pdf_buffer, region, bucket_name, timestamp)
        
        # Save metadata for future comparisons
        logger.info("Saving audit metadata...")
        save_report_metadata(bucket_name, region, scored_report, timestamp)
        
        print(f"\n{'=' * 60}")
        print("Report Generated Successfully!")
        print(f"{'=' * 60}")
        print(f"📁 S3 Location: s3://{bucket_name}/{object_key}")
        print(f"🔗 Presigned URL (1 hour): {presigned_url}")
        print(f"{'=' * 60}")
        
        # List previous reports
        previous_reports = list_previous_reports(bucket_name, region)
        if len(previous_reports) > 1:
            print(f"\n📚 Previous Reports ({len(previous_reports) - 1} found):")
            for report in previous_reports[1:6]:  # Show last 5 reports
                print(f"  • {report['key'].split('/')[-1]} - {report['last_modified'].strftime('%Y-%m-%d %H:%M:%S')}")
        print()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Audit cancelled by user")
    except Exception as e:
        logger.error(f"❌ Audit failed: {str(e)}")
        raise

if __name__ == '__main__':
    main()
