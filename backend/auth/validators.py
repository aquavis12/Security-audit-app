"""
Request validators for audit parameters
"""

from typing import List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)

class AuditRequestValidator:
    """Validates audit request parameters"""
    
    # Valid AWS regions
    VALID_REGIONS = [
        'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
        'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
        'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
        'ap-south-1', 'ca-central-1', 'sa-east-1', 'me-south-1', 'af-south-1'
    ]
    
    # Valid compliance frameworks
    VALID_FRAMEWORKS = ['CIS', 'PCI-DSS', 'HIPAA', 'NIST', 'GDPR', 'ISO27001']
    
    # Max regions per audit
    MAX_REGIONS = 3
    
    @staticmethod
    def validate_account_id(account_id: str) -> Tuple[bool, Optional[str]]:
        """
        Validate AWS account ID
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not account_id:
            return False, "Account ID is required"
        
        if not isinstance(account_id, str):
            return False, "Account ID must be a string"
        
        if not account_id.isdigit():
            return False, "Account ID must contain only digits"
        
        if len(account_id) != 12:
            return False, f"Account ID must be 12 digits, got {len(account_id)}"
        
        return True, None
    
    @staticmethod
    def validate_role_name(role_name: str) -> Tuple[bool, Optional[str]]:
        """Validate IAM role name"""
        if not role_name:
            return False, "Role name is required"
        
        if not isinstance(role_name, str):
            return False, "Role name must be a string"
        
        if len(role_name) > 64:
            return False, "Role name must be 64 characters or less"
        
        return True, None
    
    @staticmethod
    def validate_external_id(external_id: str) -> Tuple[bool, Optional[str]]:
        """Validate External ID"""
        if not external_id:
            return False, "External ID is required for security"
        
        if not isinstance(external_id, str):
            return False, "External ID must be a string"
        
        if len(external_id) < 2 or len(external_id) > 1224:
            return False, "External ID must be between 2 and 1224 characters"
        
        return True, None
    
    @staticmethod
    def validate_regions(regions: List[str]) -> Tuple[bool, Optional[str]]:
        """Validate AWS regions"""
        if not regions:
            return False, "At least one region is required"
        
        if not isinstance(regions, list):
            return False, "Regions must be a list"
        
        if len(regions) > AuditRequestValidator.MAX_REGIONS:
            return False, f"Maximum {AuditRequestValidator.MAX_REGIONS} regions allowed, got {len(regions)}"
        
        invalid_regions = [r for r in regions if r not in AuditRequestValidator.VALID_REGIONS]
        if invalid_regions:
            return False, f"Invalid regions: {', '.join(invalid_regions)}"
        
        return True, None
    
    @staticmethod
    def validate_selected_checks(checks: List[str]) -> Tuple[bool, Optional[str]]:
        """Validate selected checks"""
        if not checks:
            return False, "At least one check must be selected"
        
        if not isinstance(checks, list):
            return False, "Selected checks must be a list"
        
        if len(checks) > 50:
            return False, "Maximum 50 checks allowed per audit"
        
        return True, None
    
    @staticmethod
    def validate_compliance_frameworks(frameworks: List[str]) -> Tuple[bool, Optional[str]]:
        """Validate compliance frameworks"""
        if not frameworks:
            return True, None  # Optional parameter
        
        if not isinstance(frameworks, list):
            return False, "Compliance frameworks must be a list"
        
        invalid_frameworks = [f for f in frameworks if f not in AuditRequestValidator.VALID_FRAMEWORKS]
        if invalid_frameworks:
            return False, f"Invalid frameworks: {', '.join(invalid_frameworks)}"
        
        return True, None
    
    @classmethod
    def validate_audit_request(cls, data: dict) -> Tuple[bool, Optional[str]]:
        """
        Validate complete audit request
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        required_fields = ['accountId', 'roleName', 'externalId', 'regions', 'selectedChecks']
        
        # Check required fields
        for field in required_fields:
            if field not in data or not data[field]:
                return False, f"Missing required field: {field}"
        
        # Validate each field
        is_valid, error = cls.validate_account_id(data['accountId'])
        if not is_valid:
            return False, error
        
        is_valid, error = cls.validate_role_name(data['roleName'])
        if not is_valid:
            return False, error
        
        is_valid, error = cls.validate_external_id(data['externalId'])
        if not is_valid:
            return False, error
        
        is_valid, error = cls.validate_regions(data['regions'])
        if not is_valid:
            return False, error
        
        is_valid, error = cls.validate_selected_checks(data['selectedChecks'])
        if not is_valid:
            return False, error
        
        # Optional: validate compliance frameworks if provided
        if 'complianceFrameworks' in data:
            is_valid, error = cls.validate_compliance_frameworks(data['complianceFrameworks'])
            if not is_valid:
                return False, error
        
        return True, None
