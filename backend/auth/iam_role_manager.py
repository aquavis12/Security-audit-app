"""
IAM Role Manager - Cross-account role assumption with External ID
Inspired by Prowler's provider authentication pattern
"""

import boto3
from typing import Optional, Dict
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class IAMRoleManager:
    """Manages cross-account IAM role assumption"""
    
    def __init__(self):
        self.sts_client = None
    
    def assume_role(
        self,
        account_id: str,
        role_name: str,
        external_id: str,
        region: str = 'us-east-1',
        session_name: str = 'SecurityAuditSession',
        duration_seconds: int = 3600
    ) -> Optional[Dict[str, str]]:
        """
        Assume cross-account IAM role with mandatory External ID
        
        Args:
            account_id: Target AWS account ID (12 digits)
            role_name: IAM role name to assume
            external_id: External ID for additional security
            region: AWS region for STS client
            session_name: Session name for audit trail
            duration_seconds: Session duration (default 1 hour)
        
        Returns:
            Dictionary with temporary credentials or None if failed
        
        Raises:
            ValueError: If parameters are invalid
            ClientError: If role assumption fails
        """
        
        # Validate inputs
        if not self._validate_account_id(account_id):
            raise ValueError(f"Invalid account ID format: {account_id}. Must be 12 digits.")
        
        if not role_name or not isinstance(role_name, str):
            raise ValueError("Role name must be a non-empty string")
        
        if not external_id or not isinstance(external_id, str):
            raise ValueError("External ID is required and must be a non-empty string")
        
        try:
            # Initialize STS client if not already done
            if self.sts_client is None:
                self.sts_client = boto3.client('sts', region_name=region)
            
            # Build role ARN
            role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
            
            logger.info(f"Attempting to assume role: {role_arn}")
            
            # Assume role with External ID
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                ExternalId=external_id,
                DurationSeconds=duration_seconds
            )
            
            credentials = response['Credentials']
            
            logger.info(f"✅ Successfully assumed role: {role_arn}")
            logger.debug(f"Session expires at: {credentials['Expiration']}")
            
            return {
                'aws_access_key_id': credentials['AccessKeyId'],
                'aws_secret_access_key': credentials['SecretAccessKey'],
                'aws_session_token': credentials['SessionToken'],
                'expiration': credentials['Expiration'].isoformat()
            }
        
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            
            if error_code == 'AccessDenied':
                logger.error(f"❌ Access Denied: Check trust policy and External ID")
            elif error_code == 'ValidationError':
                logger.error(f"❌ Validation Error: {error_msg}")
            elif error_code == 'NoSuchEntity':
                logger.error(f"❌ Role not found: {role_arn}")
            else:
                logger.error(f"❌ Failed to assume role: {error_code} - {error_msg}")
            
            raise
        
        except Exception as e:
            logger.error(f"❌ Unexpected error during role assumption: {str(e)}")
            raise
    
    @staticmethod
    def _validate_account_id(account_id: str) -> bool:
        """Validate AWS account ID format"""
        return isinstance(account_id, str) and account_id.isdigit() and len(account_id) == 12
    
    @staticmethod
    def validate_role_name(role_name: str) -> bool:
        """Validate IAM role name format"""
        if not isinstance(role_name, str) or not role_name:
            return False
        # Role names can contain alphanumeric and +=,.@-
        import re
        return bool(re.match(r'^[\w+=,.@-]{1,64}$', role_name))
    
    @staticmethod
    def validate_external_id(external_id: str) -> bool:
        """Validate External ID format"""
        if not isinstance(external_id, str) or not external_id:
            return False
        # External IDs can be 2-1224 characters
        return 2 <= len(external_id) <= 1224


class AuditCredentials:
    """Wrapper for audit session credentials"""
    
    def __init__(self, credentials: Dict[str, str]):
        self.access_key_id = credentials['aws_access_key_id']
        self.secret_access_key = credentials['aws_secret_access_key']
        self.session_token = credentials['aws_session_token']
        self.expiration = credentials.get('expiration')
    
    def to_dict(self) -> Dict[str, str]:
        """Convert to dictionary for boto3 client initialization"""
        return {
            'aws_access_key_id': self.access_key_id,
            'aws_secret_access_key': self.secret_access_key,
            'aws_session_token': self.session_token
        }
    
    def is_expired(self) -> bool:
        """Check if credentials are expired"""
        if not self.expiration:
            return False
        
        from datetime import datetime, timezone
        expiration = datetime.fromisoformat(self.expiration)
        return datetime.now(timezone.utc) >= expiration
