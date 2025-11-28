"""
AWS Audit Manager Setup Script
Automatically configures AWS Audit Manager, IAM roles, and S3 bucket
"""

import boto3
import json
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class AuditManagerSetup:
    """Handles automatic setup of AWS Audit Manager prerequisites"""
    
    def __init__(self, account_id: str, region: str = 'us-east-1', credentials: dict = None):
        self.account_id = account_id
        self.region = region
        self.credentials = credentials
        self._iam_client = None
        self._s3_client = None
        self._audit_manager_client = None
    
    @property
    def iam_client(self):
        """Lazy-load IAM client"""
        if self._iam_client is None:
            kwargs = {}
            if self.credentials:
                kwargs.update({
                    'aws_access_key_id': self.credentials['aws_access_key_id'],
                    'aws_secret_access_key': self.credentials['aws_secret_access_key'],
                    'aws_session_token': self.credentials.get('aws_session_token')
                })
            self._iam_client = boto3.client('iam', **kwargs)
        return self._iam_client
    
    @property
    def s3_client(self):
        """Lazy-load S3 client"""
        if self._s3_client is None:
            kwargs = {'region_name': self.region}
            if self.credentials:
                kwargs.update({
                    'aws_access_key_id': self.credentials['aws_access_key_id'],
                    'aws_secret_access_key': self.credentials['aws_secret_access_key'],
                    'aws_session_token': self.credentials.get('aws_session_token')
                })
            self._s3_client = boto3.client('s3', **kwargs)
        return self._s3_client
    
    @property
    def audit_manager_client(self):
        """Lazy-load Audit Manager client"""
        if self._audit_manager_client is None:
            kwargs = {'region_name': self.region}
            if self.credentials:
                kwargs.update({
                    'aws_access_key_id': self.credentials['aws_access_key_id'],
                    'aws_secret_access_key': self.credentials['aws_secret_access_key'],
                    'aws_session_token': self.credentials.get('aws_session_token')
                })
            self._audit_manager_client = boto3.client('auditmanager', **kwargs)
        return self._audit_manager_client
    
    def setup_all(self) -> dict:
        """Run complete setup for AWS Audit Manager"""
        results = {
            'success': True,
            'steps': {},
            'errors': []
        }
        
        try:
            # Step 1: Create IAM role
            logger.info("Step 1: Creating IAM role for AWS Audit Manager...")
            role_result = self.create_iam_role()
            results['steps']['iam_role'] = role_result
            if not role_result['success']:
                results['errors'].append(f"IAM Role: {role_result['error']}")
            
            # Step 2: Create S3 bucket
            logger.info("Step 2: Creating S3 bucket for assessment reports...")
            s3_result = self.create_s3_bucket()
            results['steps']['s3_bucket'] = s3_result
            if not s3_result['success']:
                results['errors'].append(f"S3 Bucket: {s3_result['error']}")
            
            # Step 3: Enable Audit Manager
            logger.info("Step 3: Enabling AWS Audit Manager...")
            audit_manager_result = self.enable_audit_manager()
            results['steps']['audit_manager'] = audit_manager_result
            if not audit_manager_result['success']:
                results['errors'].append(f"Audit Manager: {audit_manager_result['error']}")
            
            # Step 4: Configure Audit Manager delegation
            logger.info("Step 4: Configuring Audit Manager delegation...")
            delegation_result = self.configure_delegation()
            results['steps']['delegation'] = delegation_result
            if not delegation_result['success']:
                results['errors'].append(f"Delegation: {delegation_result['error']}")
            
            results['success'] = len(results['errors']) == 0
            
        except Exception as e:
            logger.error(f"Setup failed: {str(e)}")
            results['success'] = False
            results['errors'].append(str(e))
        
        return results
    
    def create_iam_role(self) -> dict:
        """Create IAM role for AWS Audit Manager"""
        try:
            role_name = 'AWSAuditManagerRole'
            
            # Trust policy for Audit Manager service
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": "auditmanager.amazonaws.com"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
            
            # Check if role already exists
            try:
                self.iam_client.get_role(RoleName=role_name)
                logger.info(f"Role {role_name} already exists")
                return {
                    'success': True,
                    'message': f'Role {role_name} already exists',
                    'role_arn': f'arn:aws:iam::{self.account_id}:role/{role_name}'
                }
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    raise
            
            # Create role
            response = self.iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(trust_policy),
                Description='Role for AWS Audit Manager service'
            )
            
            # Attach policy for S3 access
            s3_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "s3:GetObject",
                            "s3:PutObject",
                            "s3:ListBucket"
                        ],
                        "Resource": [
                            f"arn:aws:s3:::aws-audit-manager-reports-{self.account_id}",
                            f"arn:aws:s3:::aws-audit-manager-reports-{self.account_id}/*"
                        ]
                    }
                ]
            }
            
            self.iam_client.put_role_policy(
                RoleName=role_name,
                PolicyName='AuditManagerS3Access',
                PolicyDocument=json.dumps(s3_policy)
            )
            
            logger.info(f"✅ Created IAM role: {role_name}")
            return {
                'success': True,
                'message': f'Created IAM role {role_name}',
                'role_arn': response['Role']['Arn']
            }
        
        except Exception as e:
            logger.error(f"Failed to create IAM role: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def create_s3_bucket(self) -> dict:
        """Create S3 bucket for assessment reports"""
        try:
            bucket_name = f'aws-audit-manager-reports-{self.account_id}'
            
            # Check if bucket already exists
            try:
                self.s3_client.head_bucket(Bucket=bucket_name)
                logger.info(f"Bucket {bucket_name} already exists")
                return {
                    'success': True,
                    'message': f'Bucket {bucket_name} already exists',
                    'bucket_name': bucket_name
                }
            except ClientError as e:
                if e.response['Error']['Code'] != '404':
                    raise
            
            # Create bucket
            if self.region == 'us-east-1':
                self.s3_client.create_bucket(Bucket=bucket_name)
            else:
                self.s3_client.create_bucket(
                    Bucket=bucket_name,
                    CreateBucketConfiguration={'LocationConstraint': self.region}
                )
            
            # Enable versioning
            self.s3_client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )
            
            # Enable encryption
            self.s3_client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    'Rules': [
                        {
                            'ApplyServerSideEncryptionByDefault': {
                                'SSEAlgorithm': 'AES256'
                            }
                        }
                    ]
                }
            )
            
            # Block public access
            self.s3_client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            
            logger.info(f"✅ Created S3 bucket: {bucket_name}")
            return {
                'success': True,
                'message': f'Created S3 bucket {bucket_name}',
                'bucket_name': bucket_name
            }
        
        except Exception as e:
            logger.error(f"Failed to create S3 bucket: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def enable_audit_manager(self) -> dict:
        """Enable AWS Audit Manager in the account"""
        try:
            # Register delegated administrator (if in organization)
            try:
                response = self.audit_manager_client.register_account()
                logger.info("✅ Registered AWS Audit Manager account")
                return {
                    'success': True,
                    'message': 'AWS Audit Manager enabled',
                    'status': response.get('status')
                }
            except ClientError as e:
                if 'already' in str(e).lower():
                    logger.info("AWS Audit Manager already enabled")
                    return {
                        'success': True,
                        'message': 'AWS Audit Manager already enabled'
                    }
                raise
        
        except Exception as e:
            logger.error(f"Failed to enable Audit Manager: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def configure_delegation(self) -> dict:
        """Configure Audit Manager delegation settings"""
        try:
            # Update settings
            response = self.audit_manager_client.update_settings(
                snapshotDestination={
                    'destinationType': 'S3',
                    'destination': f's3://aws-audit-manager-reports-{self.account_id}'
                }
            )
            
            logger.info("✅ Configured Audit Manager delegation")
            return {
                'success': True,
                'message': 'Audit Manager delegation configured',
                'settings': response.get('settings')
            }
        
        except Exception as e:
            logger.error(f"Failed to configure delegation: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
