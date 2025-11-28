"""
AWS Audit Manager Integration Service
Fetches compliance assessments and findings from AWS Audit Manager
"""

import boto3
from typing import Optional, Dict, List, Any
import logging
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class AuditManagerService:
    """Integrates with AWS Audit Manager for compliance tracking"""
    
    def __init__(self, region: str = 'us-east-1', credentials: Optional[Dict] = None):
        self.region = region
        self.credentials = credentials
        self._client = None
    
    @property
    def client(self):
        """Lazy-load Audit Manager client"""
        if self._client is None:
            client_kwargs = {'region_name': self.region}
            if self.credentials:
                client_kwargs.update({
                    'aws_access_key_id': self.credentials['aws_access_key_id'],
                    'aws_secret_access_key': self.credentials['aws_secret_access_key'],
                    'aws_session_token': self.credentials['aws_session_token']
                })
            self._client = boto3.client('auditmanager', **client_kwargs)
        return self._client
    
    def get_assessments(self) -> List[Dict[str, Any]]:
        """Get all assessments from Audit Manager"""
        try:
            logger.info("Fetching assessments from AWS Audit Manager...")
            
            assessments = []
            next_token = None
            
            while True:
                # Build request parameters
                params = {}
                if next_token:
                    params['nextToken'] = next_token
                
                # Call list_assessments API
                response = self.client.list_assessments(**params)
                
                # Process assessments
                for assessment in response.get('assessmentMetadata', []):
                    assessments.append({
                        'id': assessment.get('id'),
                        'name': assessment.get('name'),
                        'status': assessment.get('status'),
                        'framework': assessment.get('complianceType'),
                        'created_at': str(assessment.get('creationTime')) if assessment.get('creationTime') else None,
                        'last_updated': str(assessment.get('lastUpdated')) if assessment.get('lastUpdated') else None
                    })
                
                # Check for more pages
                next_token = response.get('nextToken')
                if not next_token:
                    break
            
            logger.info(f"Found {len(assessments)} assessments")
            return assessments
        
        except ClientError as e:
            logger.error(f"Error fetching assessments: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching assessments: {e}")
            return []
    
    def get_assessment_details(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific assessment"""
        try:
            logger.info(f"Fetching assessment details: {assessment_id}")
            
            response = self.client.get_assessment(assessmentId=assessment_id)
            assessment = response.get('assessment', {})
            
            return {
                'id': assessment.get('arn'),
                'name': assessment.get('metadata', {}).get('name'),
                'status': assessment.get('metadata', {}).get('status'),
                'framework': assessment.get('metadata', {}).get('complianceType'),
                'findings_count': len(assessment.get('findings', [])),
                'evidence_count': len(assessment.get('evidence', [])),
                'created_at': assessment.get('metadata', {}).get('creationTime'),
                'last_updated': assessment.get('metadata', {}).get('lastUpdated')
            }
        
        except ClientError as e:
            logger.error(f"Error fetching assessment details: {e}")
            return None
    
    def get_compliance_frameworks(self) -> List[Dict[str, Any]]:
        """Get available compliance frameworks"""
        try:
            logger.info("Fetching compliance frameworks...")
            
            frameworks = []
            next_token = None
            
            while True:
                # Build request parameters
                params = {'frameworkType': 'Standard'}
                if next_token:
                    params['nextToken'] = next_token
                
                # Call list_assessment_frameworks API
                response = self.client.list_assessment_frameworks(**params)
                
                # Process frameworks
                for framework in response.get('frameworkMetadataList', []):
                    frameworks.append({
                        'id': framework.get('id'),
                        'name': framework.get('name'),
                        'type': framework.get('type'),
                        'controls_count': framework.get('controlsCount'),
                        'description': framework.get('description')
                    })
                
                # Check for more pages
                next_token = response.get('nextToken')
                if not next_token:
                    break
            
            logger.info(f"Found {len(frameworks)} frameworks")
            return frameworks
        
        except ClientError as e:
            logger.error(f"Error fetching frameworks: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching frameworks: {e}")
            return []
    
    def get_assessment_findings(self, assessment_id: str) -> List[Dict[str, Any]]:
        """Get findings from a specific assessment"""
        try:
            logger.info(f"Fetching findings for assessment: {assessment_id}")
            
            findings = []
            next_token = None
            
            while True:
                # Build request parameters
                params = {'assessmentId': assessment_id}
                if next_token:
                    params['nextToken'] = next_token
                
                # Call list_assessment_control_insights_by_control_domain API or similar
                # Note: AWS Audit Manager doesn't have a direct "get findings" API
                # We'll use get_assessment to get the assessment data
                response = self.client.get_assessment(assessmentId=assessment_id)
                assessment = response.get('assessment', {})
                
                # Get control sets and their controls
                for control_set in assessment.get('framework', {}).get('controlSets', []):
                    for control in control_set.get('controls', []):
                        if control.get('status') == 'REVIEWED':
                            findings.append({
                                'id': control.get('id'),
                                'name': control.get('name'),
                                'status': control.get('status'),
                                'description': control.get('description'),
                                'evidence_count': len(control.get('evidenceIds', []))
                            })
                
                # No pagination for get_assessment
                break
            
            logger.info(f"Found {len(findings)} findings")
            return findings
        
        except ClientError as e:
            logger.error(f"Error fetching findings: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error fetching findings: {e}")
            return []
    
    def get_compliance_summary(self, assessment_id: str) -> Dict[str, Any]:
        """Get compliance summary for an assessment"""
        try:
            response = self.client.get_assessment(assessmentId=assessment_id)
            assessment = response.get('assessment', {})
            
            findings = assessment.get('findings', [])
            
            # Count findings by status
            compliant = sum(1 for f in findings if f.get('findingStatus') == 'COMPLIANT')
            non_compliant = sum(1 for f in findings if f.get('findingStatus') == 'NON_COMPLIANT')
            
            total = len(findings)
            compliance_percentage = int((compliant / total * 100)) if total > 0 else 0
            
            return {
                'assessment_id': assessment_id,
                'total_findings': total,
                'compliant': compliant,
                'non_compliant': non_compliant,
                'compliance_percentage': compliance_percentage,
                'status': assessment.get('metadata', {}).get('status')
            }
        
        except ClientError as e:
            logger.error(f"Error getting compliance summary: {e}")
            return {}
