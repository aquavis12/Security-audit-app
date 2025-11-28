"""
Compliance Audit Engine
Orchestrates AWS Audit Manager-based compliance audits
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
from backend.services.audit_manager_service import AuditManagerService
from backend.auth.iam_role_manager import IAMRoleManager
from backend.audit_modes import ComplianceAuditConfig

logger = logging.getLogger(__name__)

class ComplianceAuditEngine:
    """Manages compliance audits using AWS Audit Manager"""
    
    def __init__(self):
        self.iam_manager = IAMRoleManager()
    
    def run_compliance_audit(self, config: ComplianceAuditConfig) -> Dict[str, Any]:
        """
        Run a compliance audit using AWS Audit Manager
        
        Args:
            config: ComplianceAuditConfig with audit parameters
        
        Returns:
            Dictionary with audit results
        """
        try:
            logger.info(f"Starting compliance audit for account {config.account_id}")
            
            # Assume role
            credentials = self.iam_manager.assume_role(
                account_id=config.account_id,
                role_name=config.role_name,
                external_id=config.external_id,
                region=config.region
            )
            
            logger.info("✅ Successfully assumed role")
            
            # Initialize Audit Manager service
            audit_manager = AuditManagerService(
                region=config.region,
                credentials=credentials
            )
            
            # Get or create assessment
            assessment_id = config.assessment_id
            
            if not assessment_id and config.create_new_assessment:
                if not config.framework_id:
                    raise ValueError("Framework ID is required when creating a new assessment. Please select a framework.")
                
                logger.info(f"Creating new assessment: {config.assessment_name}")
                assessment_id = self._create_assessment(
                    audit_manager,
                    config.assessment_name,
                    config.framework_id,
                    config.account_id
                )
            
            if not assessment_id:
                raise ValueError("No assessment ID provided or created. Please either select an existing assessment or provide a framework to create a new one.")
            
            logger.info(f"Using assessment: {assessment_id}")
            
            # Get assessment details
            assessment_details = audit_manager.get_assessment_details(assessment_id)
            
            # Get findings
            findings = audit_manager.get_assessment_findings(assessment_id)
            
            # Get compliance summary
            summary = audit_manager.get_compliance_summary(assessment_id)
            
            # Get frameworks
            frameworks = audit_manager.get_compliance_frameworks()
            
            # Build results
            results = {
                'success': True,
                'audit_mode': 'compliance_audit',
                'assessment_id': assessment_id,
                'assessment': assessment_details,
                'findings': findings,
                'summary': summary,
                'frameworks': frameworks,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'account_id': config.account_id,
                'region': config.region
            }
            
            logger.info(f"✅ Compliance audit completed: {summary.get('compliance_percentage', 0)}% compliant")
            
            return results
        
        except Exception as e:
            logger.error(f"❌ Compliance audit failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'audit_mode': 'compliance_audit'
            }
    
    def _create_assessment(
        self,
        audit_manager: AuditManagerService,
        assessment_name: str,
        framework_id: Optional[str] = None,
        account_id: Optional[str] = None
    ) -> Optional[str]:
        """Create a new assessment in AWS Audit Manager"""
        try:
            # Get available frameworks if not specified
            if not framework_id:
                frameworks = audit_manager.get_compliance_frameworks()
                if frameworks:
                    framework_id = frameworks[0]['id']
                    logger.info(f"Using default framework: {frameworks[0]['name']}")
                else:
                    logger.error("No frameworks available")
                    return None
            
            if not framework_id:
                logger.error("Framework ID is required")
                return None
            
            # Build scope - this is required by AWS Audit Manager
            scope = {
                'awsAccounts': [],
                'awsServices': []
            }
            
            # Add account to scope if provided
            if account_id:
                scope['awsAccounts'] = [{'id': account_id}]
            
            # Create assessment via boto3 client
            response = audit_manager.client.create_assessment(
                name=assessment_name,
                description=f"Compliance assessment created by SecAuditTool",
                scope=scope,
                assessmentReportsDestination={
                    'destinationType': 'S3',
                    'destination': f's3://aws-audit-manager-reports-{account_id}' if account_id else 's3://aws-audit-manager-reports'
                },
                frameworkId=framework_id,
                roles=[
                    {
                        'roleType': 'PROCESS_OWNER',
                        'roleArn': f'arn:aws:iam::{account_id}:role/service-role/AWSAuditManagerRole' if account_id else 'arn:aws:iam::aws:role/service-role/AWSAuditManagerRole'
                    }
                ]
            )
            
            assessment_id = response['assessment']['arn']
            logger.info(f"✅ Created assessment: {assessment_id}")
            return assessment_id
        
        except Exception as e:
            logger.error(f"Failed to create assessment: {str(e)}")
            return None
    
    def get_assessment_status(
        self,
        account_id: str,
        role_name: str,
        external_id: str,
        region: str,
        assessment_id: str
    ) -> Dict[str, Any]:
        """Get current status of an assessment"""
        try:
            credentials = self.iam_manager.assume_role(
                account_id=account_id,
                role_name=role_name,
                external_id=external_id,
                region=region
            )
            
            audit_manager = AuditManagerService(
                region=region,
                credentials=credentials
            )
            
            details = audit_manager.get_assessment_details(assessment_id)
            summary = audit_manager.get_compliance_summary(assessment_id)
            
            return {
                'success': True,
                'assessment': details,
                'summary': summary
            }
        
        except Exception as e:
            logger.error(f"Failed to get assessment status: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def list_assessments(
        self,
        account_id: str,
        role_name: str,
        external_id: str,
        region: str
    ) -> Dict[str, Any]:
        """List all assessments in an account"""
        try:
            credentials = self.iam_manager.assume_role(
                account_id=account_id,
                role_name=role_name,
                external_id=external_id,
                region=region
            )
            
            audit_manager = AuditManagerService(
                region=region,
                credentials=credentials
            )
            
            assessments = audit_manager.get_assessments()
            frameworks = audit_manager.get_compliance_frameworks()
            
            return {
                'success': True,
                'assessments': assessments,
                'frameworks': frameworks
            }
        
        except Exception as e:
            logger.error(f"Failed to list assessments: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
