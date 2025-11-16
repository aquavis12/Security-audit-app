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
SEVERITY_MAP = {
    'EC2_SG_OPEN_0_0_0_0': 3,
    'S3_PUBLIC_BUCKET': 3,
    'IAM_USER_INACTIVE': 1,
    'IAM_ACCESS_KEY_UNUSED': 1,
    'EBS_UNENCRYPTED': 2,
    'RDS_UNENCRYPTED': 2,
    'AURORA_UNENCRYPTED': 2,
    'IAM_ROLE_UNUSED': 0,
    'BACKUP_VAULT_UNENCRYPTED': 2,
    'EC2_NO_IMDSV2': 2,
    'EC2_UNUSED_KEY_PAIR': 1,
    'ECS_ENCRYPTION_ISSUE': 2,
    'API_GW_LOG_UNENCRYPTED': 2,
    'CLOUDFRONT_ENCRYPTION_ISSUE': 2,
    'RDS_AURORA_BACKUP_UNENCRYPTED': 3,
    'UNUSED_KMS_KEYS': 0,
    'UNUSED_SECRETS': 1,
    'PARAMETER_STORE_ISSUE': 1
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
                                'Description': sg.get('Description', 'No description')[:50],
                                'Remediation': f'aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol {protocol} --port {from_port} --cidr 0.0.0.0/0'
                            })
                            break
            
            logger.info(f"Found {len(open_sgs)} open security groups (excluding ALB/NLB)")
            return open_sgs
        except Exception as e:
            logger.error(f"Error checking security groups: {str(e)}")
            return []

    def check_s3_public_buckets(self):
        """Check for publicly accessible S3 buckets"""
        try:
            logger.info("Checking S3 public buckets...")
            buckets = self.s3.list_buckets().get('Buckets', [])
            public_buckets = []
            for bucket in buckets:
                try:
                    bucket_name = bucket['Name']
                    creation_date = bucket.get('CreationDate', 'Unknown')
                    if creation_date != 'Unknown':
                        creation_date = creation_date.strftime('%Y-%m-%d')
                    
                    acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            public_buckets.append({
                                'BucketName': bucket_name,
                                'Created': creation_date,
                                'Access': 'Public (AllUsers)',
                                'Permission': grant.get('Permission', 'Unknown'),
                                'Recommendation': f'Remove public access from bucket: aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"'
                            })
                            break
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
                                    'Policy': json.dumps(stmt, indent=2)[:200],
                                    'Remediation': f'Review and restrict bucket policy for {bucket["Name"]} - Remove wildcard permissions'
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
        clusters = self.rds.describe_db_clusters().get('DBClusters', [])
        unencrypted = [c['DBClusterIdentifier'] for c in clusters if not c.get('StorageEncrypted', False)]
        return unencrypted

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
        vaults = self.backup.list_backup_vaults().get('BackupVaultList', [])
        unencrypted = [v['BackupVaultName'] for v in vaults if not v.get('EncryptionKeyArn')]
        return unencrypted

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

    def check_unused_key_pairs(self):
        key_pairs = self.ec2.describe_key_pairs().get('KeyPairs', [])
        reservations = self.ec2.describe_instances().get('Reservations', [])
        used_key_names = set()
        for res in reservations:
            for inst in res.get('Instances', []):
                if 'KeyName' in inst:
                    used_key_names.add(inst['KeyName'])
        unused_keys = [kp['KeyName'] for kp in key_pairs if kp['KeyName'] not in used_key_names]
        return unused_keys

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
                                    'LastModified': last_mod.strftime('%Y-%m-%d'),
                                    'Recommendation': f'Review and delete unused parameter: {param["Name"]}'
                                })
                    except Exception:
                        continue
            logger.info(f"Found {len(stale_params)} stale parameters (not modified in {days}+ days)")
            return stale_params
        except Exception as e:
            logger.error(f"Error checking Parameter Store: {str(e)}")
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

def get_recommendation(check_name):
    """Get security recommendation for each check"""
    recommendations = {
        'EC2_SG_OPEN_0_0_0_0': 'Restrict security groups to specific IP ranges immediately',
        'S3_PUBLIC_BUCKET': 'Remove public access and use presigned URLs or CloudFront',
        'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS': 'Review and restrict bucket policies - Remove wildcard (*) permissions',
        'IAM_USER_INACTIVE': 'Disable or delete inactive users to reduce attack surface',
        'IAM_ACCESS_KEY_UNUSED': 'Rotate or delete unused access keys immediately',
        'IAM_ROLE_UNUSED': 'Review and delete unused IAM roles (keep AWS service roles)',
        'EBS_UNENCRYPTED': 'Enable encryption for all EBS volumes using AWS KMS',
        'RDS_UNENCRYPTED': 'Enable encryption at rest for RDS instances',
        'AURORA_UNENCRYPTED': 'Enable encryption for Aurora clusters',
        'RDS_AURORA_BACKUP_UNENCRYPTED': 'Enable backup encryption for all databases',
        'EC2_NO_IMDSV2': 'Enforce IMDSv2 to prevent SSRF attacks',
        'EC2_UNUSED_KEY_PAIR': 'Delete unused EC2 key pairs to reduce security risks',
        'BACKUP_VAULT_UNENCRYPTED': 'Enable encryption for AWS Backup vaults using KMS',
        'ECS_ENCRYPTION_ISSUE': 'Enable encryption for ECS task storage and secrets',
        'API_GW_LOG_UNENCRYPTED': 'Enable KMS encryption for API Gateway CloudWatch logs',
        'CLOUDFRONT_ENCRYPTION_ISSUE': 'Enforce HTTPS-only for all CloudFront distributions',
        'UNUSED_KMS_KEYS': 'Delete or disable unused KMS keys to reduce costs',
        'UNUSED_SECRETS': 'Delete unused secrets from AWS Secrets Manager',
        'PARAMETER_STORE_ISSUE': 'Review and delete unused SSM parameters not modified in 60+ days',
    }
    return recommendations.get(check_name, 'Review and remediate this security finding')

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
    """Get a random AWS security-related quote"""
    quotes = [
        {
            'text': 'Security is job zero at AWS. We build security into everything we do, and we make it easy for customers to implement security best practices.',
            'author': 'AWS Security Team'
        },
        {
            'text': 'In AWS, security is a shared responsibility. AWS secures the cloud, you secure what you put in the cloud.',
            'author': 'AWS Shared Responsibility Model'
        },
        {
            'text': 'Encrypt everything. Use IAM roles, not keys. Enable MFA. Follow the principle of least privilege. These are not optional in AWS.',
            'author': 'AWS Security Best Practices'
        },
        {
            'text': 'The best time to implement AWS security controls was at launch. The second best time is now.',
            'author': 'Cloud Security Wisdom'
        },
        {
            'text': 'An open security group to 0.0.0.0/0 is not a feature, it is a vulnerability waiting to be exploited.',
            'author': 'AWS Security Audit'
        },
        {
            'text': 'Defense in depth: Use VPCs, security groups, NACLs, WAF, encryption, and monitoring. Layer your AWS security.',
            'author': 'AWS Well-Architected Framework'
        },
        {
            'text': 'Unused IAM credentials are like unlocked doors. Delete them before someone walks through.',
            'author': 'AWS IAM Best Practices'
        },
        {
            'text': 'Enable CloudTrail, GuardDuty, and Security Hub. You cannot protect what you cannot see.',
            'author': 'AWS Security Monitoring'
        },
        {
            'text': 'Encryption at rest and in transit is not paranoia in AWS, it is compliance and common sense.',
            'author': 'AWS Encryption Standards'
        },
        {
            'text': 'Regular security audits are not about finding problems, they are about preventing disasters.',
            'author': 'AWS Security Operations'
        },
        {
            'text': 'IMDSv2 is not optional. SSRF attacks are real. Protect your EC2 instance metadata.',
            'author': 'AWS EC2 Security'
        },
        {
            'text': 'Public S3 buckets have caused more data breaches than any other AWS misconfiguration. Block public access by default.',
            'author': 'AWS S3 Security'
        }
    ]
    return random.choice(quotes)

def create_pdf_report(scored_report, region, comparison=None):
    """Create a colorful, well-structured PDF report with optional comparison"""
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import inch
    from reportlab.platypus import Table, TableStyle
    
    buffer = BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Get account info and additional details
    try:
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
    severity_names = {3: "CRITICAL", 2: "HIGH", 1: "MEDIUM", 0: "LOW"}
    
    def draw_header(canvas_obj, page_num=1):
        """Draw enhanced page header with professional blue/white design"""
        # Header background - Professional blue
        canvas_obj.setFillColor(colors.HexColor('#1565C0'))
        canvas_obj.rect(0, height - 85, width, 85, fill=True, stroke=False)
        
        # Accent line - Light blue
        canvas_obj.setFillColor(colors.HexColor('#42A5F5'))
        canvas_obj.rect(0, height - 90, width, 5, fill=True, stroke=False)
        
        # Shield icon (simulated with text)
        canvas_obj.setFillColor(colors.white)
        canvas_obj.setFont("Helvetica-Bold", 28)
        canvas_obj.drawString(50, height - 52, "🛡")
        
        # Title
        canvas_obj.setFillColor(colors.white)
        canvas_obj.setFont("Helvetica-Bold", 24)
        canvas_obj.drawString(95, height - 40, "AWS Security Audit Report")
        
        # Subtitle
        canvas_obj.setFont("Helvetica", 11)
        canvas_obj.setFillColor(colors.HexColor('#E3F2FD'))
        canvas_obj.drawString(95, height - 60, f"Region: {region} | Powered by SUDO")
        
        # Page number in corner
        canvas_obj.setFillColor(colors.white)
        canvas_obj.setFont("Helvetica", 10)
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
        canvas_obj.setFont("Helvetica", 9)
        
        # Left side - Account info
        if account_name:
            canvas_obj.drawString(50, 42, f"Account: {account_id} ({account_name})")
        else:
            canvas_obj.drawString(50, 42, f"Account: {account_id}")
        
        # Center - Region
        canvas_obj.drawString(280, 42, f"Region: {region}")
        
        # Right side - Scan date
        canvas_obj.drawString(420, 42, f"Scan: {scan_date}")
        
        # Bottom left - Branding
        canvas_obj.setFont("Helvetica-Bold", 9)
        canvas_obj.setFillColor(colors.HexColor('#1565C0'))
        canvas_obj.drawString(50, 22, "Powered by SUDO")
        
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.setFillColor(colors.HexColor('#757575'))
        canvas_obj.drawString(50, 12, "AWS Security Audit Tool")
        
        # Bottom right - Confidentiality
        canvas_obj.setFont("Helvetica-Bold", 9)
        canvas_obj.setFillColor(colors.HexColor('#d32f2f'))
        canvas_obj.drawRightString(width - 50, 22, "⚠ CONFIDENTIAL")
        
        canvas_obj.setFont("Helvetica", 8)
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
        canvas_obj.setFont("Helvetica-Bold", 18)
        canvas_obj.drawString(70, box_y + 70, "📋 Account Information")
        
        # Details
        canvas_obj.setFont("Helvetica", 11)
        canvas_obj.setFillColor(colors.HexColor('#424242'))
        canvas_obj.drawString(70, box_y + 50, f"Account ID: {acc_id}")
        canvas_obj.drawString(70, box_y + 35, f"Region: {reg}")
        canvas_obj.drawString(70, box_y + 20, f"Scan Date: {scan_dt}")
        
        # Compliance Status
        canvas_obj.setFont("Helvetica-Bold", 12)
        canvas_obj.setFillColor(colors.HexColor('#424242'))
        canvas_obj.drawString(400, box_y + 45, "Compliance Status:")
        canvas_obj.setFont("Helvetica-Bold", 11)
        if crit_count > 0:
            canvas_obj.setFillColor(colors.HexColor('#d32f2f'))
            canvas_obj.drawString(400, box_y + 28, "⚠ Non-Compliant")
        else:
            canvas_obj.setFillColor(colors.HexColor('#388e3c'))
            canvas_obj.drawString(400, box_y + 28, "✓ Compliant")
        
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
        canvas_obj.setFont("Helvetica-Bold", 17)
        canvas_obj.drawString(70, box_y + 70, "📝 Executive Summary")
        
        # Summary text
        canvas_obj.setFont("Helvetica", 10)
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
        canvas_obj.setFont("Helvetica", 9)
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
        canvas_obj.setFont("Helvetica-Bold", 18)
        canvas_obj.drawString(70, box_y + 90, "📊 Findings Breakdown")
        
        # Security Status - large and prominent
        canvas_obj.setFont("Helvetica-Bold", 18)
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
            canvas_obj.setFont("Helvetica-Bold", 11)
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
    
    # Findings section
    y -= 35
    c.setFillColor(colors.HexColor('#0D47A1'))
    c.setFont("Helvetica-Bold", 20)
    c.drawString(50, y, "Detailed Findings")
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
        c.setFont("Helvetica-Bold", 9)
        c.drawCentredString(50 + badge_width/2, y - 13, sev_text)
        
        # Draw finding title (without count) - make it readable
        c.setFillColor(colors.HexColor('#0D47A1'))
        c.setFont("Helvetica-Bold", 16)
        
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
        c.setFont("Helvetica", 13)
        c.setFillColor(colors.HexColor('#757575'))
        c.drawString(135 + c.stringWidth(readable_title, "Helvetica-Bold", 16) + 12, y - 16, f"({entry['count']})")
        c.setFillColor(colors.black)
        
        y -= 35
        
        # Draw items with enhanced formatting
        c.setFont("Helvetica", 10)
        
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
                        item_text = f"• {item['BucketName']} | Created: {item.get('Created', 'Unknown')} | Risk: {item.get('Risk', 'Unknown')}"
                        aws_url = 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html'
                    else:
                        # Public bucket
                        item_text = f"• {item['BucketName']} | Created: {item.get('Created', 'Unknown')} | Access: {item.get('Access', 'Public')} | Permission: {item.get('Permission', 'Unknown')}"
                        aws_url = 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html'
                    c.drawString(70, y, item_text)
                    y -= 15
                    
                    # Add remediation (check both Recommendation and Remediation fields)
                    remediation_text = item.get('Recommendation') or item.get('Remediation')
                    if remediation_text and y > 130:
                        c.setFont("Helvetica-Oblique", 9)
                        c.setFillColor(colors.HexColor('#1565C0'))
                        c.drawString(90, y, f"Fix: {remediation_text[:85]}")
                        y -= 13
                        
                        # Add AWS documentation URL
                        c.setFont("Helvetica", 8)
                        c.setFillColor(colors.HexColor('#1565C0'))
                        c.drawString(90, y, f"📚 AWS Docs: {aws_url}")
                        y -= 13
                        
                        c.setFont("Helvetica", 10)
                        c.setFillColor(colors.HexColor('#424242'))
                    continue
                elif 'VolumeId' in item:
                    # EBS Volume
                    c.setFillColor(colors.HexColor('#424242'))
                    item_text = f"• {item['VolumeId']} - {item['Size']} ({item['Type']}, {item['State']})"
                elif 'DBInstanceIdentifier' in item:
                    # RDS Instance
                    c.setFillColor(colors.HexColor('#424242'))
                    item_text = f"• {item['DBInstanceIdentifier']} - {item['Engine']} ({item['Size']}, {item['Status']})"
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
        
        # Add detailed recommendation box for ALL findings with AWS documentation URL
        # Force page break if not enough space
        if y < 150:
            draw_footer(c)
            c.showPage()
            page_num += 1
            draw_header(c, page_num)
            y = height - 110
        
        # Color-code recommendation box by severity
        if severity == 3:
            box_color = colors.HexColor('#FFEBEE')
            border_color = colors.HexColor('#d32f2f')
            title_color = colors.HexColor('#b71c1c')
            title_text = "⚠ IMMEDIATE ACTION REQUIRED"
            impact_text = "Impact: Critical security risk - Potential data breach or unauthorized access"
            timeline_text = "Timeline: Fix within 24-48 hours"
        elif severity == 2:
            box_color = colors.HexColor('#FFF3E0')
            border_color = colors.HexColor('#f57c00')
            title_color = colors.HexColor('#e65100')
            title_text = "⚠ HIGH PRIORITY ACTION"
            impact_text = "Impact: High security risk - Should be addressed promptly"
            timeline_text = "Timeline: Fix within 1 week"
        elif severity == 1:
            box_color = colors.HexColor('#FFFDE7')
            border_color = colors.HexColor('#fbc02d')
            title_color = colors.HexColor('#f57f17')
            title_text = "⚡ MEDIUM PRIORITY"
            impact_text = "Impact: Medium security risk - Address in next maintenance window"
            timeline_text = "Timeline: Fix within 2 weeks"
        else:
            box_color = colors.HexColor('#E8F5E9')
            border_color = colors.HexColor('#8bc34a')
            title_color = colors.HexColor('#558b2f')
            title_text = "ℹ LOW PRIORITY"
            impact_text = "Impact: Low security risk - Address during regular reviews"
            timeline_text = "Timeline: Fix within 1 month"
        
        c.setFillColor(box_color)
        c.setStrokeColor(border_color)
        c.setLineWidth(2)
        c.roundRect(70, y - 85, width - 140, 80, 8, fill=True, stroke=True)
        
        c.setFillColor(title_color)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(80, y - 18, title_text)
        
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.HexColor('#424242'))
        c.drawString(80, y - 33, f"Recommendation: {get_recommendation(entry['check'])}")
        c.drawString(80, y - 48, impact_text)
        c.drawString(80, y - 63, timeline_text)
        
        # Add AWS documentation URL
        aws_url = get_aws_documentation_url(entry['check'])
        c.setFont("Helvetica", 9)
        c.setFillColor(colors.HexColor('#1565C0'))
        c.drawString(80, y - 78, f"📚 AWS Documentation: {aws_url}")
        
        y -= 90
        
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
        # Generate default bucket name
        account_id = boto3.client('sts').get_caller_identity()['Account']
        bucket_name = f"aws-security-audit-{account_id}-{region}"
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
                            print(f"  • {item['BucketName']} | Created: {item.get('Created', 'Unknown')} | Risk: {item.get('Risk', 'Unknown')}")
                            aws_url = 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html'
                        else:
                            # Public bucket
                            print(f"  • {item['BucketName']} | Created: {item.get('Created', 'Unknown')} | Access: {item.get('Access', 'Public')} | Permission: {item.get('Permission', 'Unknown')}")
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
                        print(f"  • {item['VolumeId']} - {item['Size']} ({item['Type']})")
                    elif 'DBInstanceIdentifier' in item:
                        print(f"  • {item['DBInstanceIdentifier']} - {item['Engine']} ({item['Size']})")
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
