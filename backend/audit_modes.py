"""
Audit Modes - Two distinct audit workflows
1. Security Checks Mode - Custom security checks
2. Compliance Audit Mode - AWS Audit Manager integration
"""

from enum import Enum
from dataclasses import dataclass
from typing import List, Optional

class AuditMode(Enum):
    """Available audit modes"""
    SECURITY_CHECKS = "security_checks"
    COMPLIANCE_AUDIT = "compliance_audit"

@dataclass
class SecurityCheckConfig:
    """Configuration for security checks mode"""
    account_id: str
    role_name: str
    external_id: str
    regions: List[str]
    selected_checks: List[str]
    s3_bucket: Optional[str] = None

@dataclass
class ComplianceAuditConfig:
    """Configuration for compliance audit mode"""
    account_id: str
    role_name: str
    external_id: str
    region: str
    framework_id: Optional[str] = None  # Specific framework to audit
    assessment_id: Optional[str] = None  # Existing assessment to use
    create_new_assessment: bool = True  # Create new assessment if not provided
    assessment_name: Optional[str] = None
    s3_bucket: Optional[str] = None

class AuditModeValidator:
    """Validates audit mode configurations"""
    
    @staticmethod
    def validate_security_check_config(config: SecurityCheckConfig) -> tuple[bool, Optional[str]]:
        """Validate security check configuration"""
        if not config.account_id or not config.account_id.isdigit() or len(config.account_id) != 12:
            return False, "Invalid account ID"
        
        if not config.role_name:
            return False, "Role name is required"
        
        if not config.external_id:
            return False, "External ID is required"
        
        if not config.regions or len(config.regions) == 0:
            return False, "At least one region is required"
        
        if len(config.regions) > 3:
            return False, "Maximum 3 regions allowed"
        
        if not config.selected_checks or len(config.selected_checks) == 0:
            return False, "At least one check must be selected"
        
        return True, None
    
    @staticmethod
    def validate_compliance_audit_config(config: ComplianceAuditConfig) -> tuple[bool, Optional[str]]:
        """Validate compliance audit configuration"""
        if not config.account_id or not config.account_id.isdigit() or len(config.account_id) != 12:
            return False, "Invalid account ID"
        
        if not config.role_name:
            return False, "Role name is required"
        
        if not config.external_id:
            return False, "External ID is required"
        
        if not config.region:
            return False, "Region is required"
        
        if config.create_new_assessment and not config.assessment_name:
            return False, "Assessment name is required when creating new assessment"
        
        return True, None
