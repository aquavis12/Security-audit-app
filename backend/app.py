"""
Flask Backend for AWS Security Audit Application
Provides REST API for running security audits with cross-account role assumption
"""

import os
import json
import boto3
from flask import Flask, request, jsonify, render_template, redirect, send_file
from datetime import datetime, timezone
import logging
from io import BytesIO
import sys

# Import the security audit class from same directory
try:
    from .sa import (
        AWSecurityAudit, 
        create_pdf_report, 
        SEVERITY_MAP,
        upload_pdf_to_s3,
        create_s3_bucket_if_not_exists,
        save_report_metadata,
        utcnow
    )
    from .dynamodb_service import DynamoDBService
    from .auth.iam_role_manager import IAMRoleManager, AuditCredentials
    from .auth.validators import AuditRequestValidator
    from .services.audit_manager_service import AuditManagerService
    from .compliance_audit_engine import ComplianceAuditEngine
    from .audit_modes import AuditMode, SecurityCheckConfig, ComplianceAuditConfig, AuditModeValidator
    from .setup_audit_manager import AuditManagerSetup
except ImportError:
    from sa import (
        AWSecurityAudit, 
        create_pdf_report, 
        SEVERITY_MAP,
        upload_pdf_to_s3,
        create_s3_bucket_if_not_exists,
        save_report_metadata,
        utcnow
    )
    from dynamodb_service import DynamoDBService
    from auth.iam_role_manager import IAMRoleManager, AuditCredentials
    from auth.validators import AuditRequestValidator
    from services.audit_manager_service import AuditManagerService
    from compliance_audit_engine import ComplianceAuditEngine
    from audit_modes import AuditMode, SecurityCheckConfig, ComplianceAuditConfig, AuditModeValidator
    from setup_audit_manager import AuditManagerSetup

# Initialize services
db_service = DynamoDBService()
iam_role_manager = IAMRoleManager()
validator = AuditRequestValidator()
compliance_engine = ComplianceAuditEngine()
mode_validator = AuditModeValidator()

# Configure Flask with templates
app = Flask(__name__, template_folder='../templates')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    """Serve main page - redirect to audit modes"""
    return redirect('/audit-modes')

@app.route('/dashboard')
def dashboard():
    """Serve unified dashboard page - redirects to security checks dashboard"""
    return redirect('/dashboard/security-checks')

@app.route('/dashboard/security-checks')
def dashboard_security_checks():
    """Serve security checks dashboard with usage statistics"""
    try:
        stats = db_service.get_dashboard_stats(audit_mode='security_checks')
        return render_template('dashboard-security-checks.html', stats=stats, user={'name': 'User', 'role': 'admin'})
    except Exception as e:
        logger.error(f"Error loading security checks dashboard: {e}")
        # Return dashboard with empty stats if DynamoDB not available
        return render_template('dashboard-security-checks.html', stats={
            'total_reports': 0,
            'total_findings': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0,
            'compliance_score': 0,
            'accounts_scanned': 0,
            'regions_scanned': 0,
            'recent_reports': [],
            'chart_months': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
            'chart_counts': [0, 0, 0, 0, 0, 0],
            'severity_trends': {'critical': [0]*6, 'high': [0]*6, 'medium': [0]*6, 'low': [0]*6}
        }, user={'name': 'User', 'role': 'admin'})

@app.route('/dashboard/compliance-audit')
def dashboard_compliance_audit():
    """Serve compliance audit dashboard with assessment statistics"""
    try:
        stats = db_service.get_dashboard_stats(audit_mode='compliance_audit')
        return render_template('dashboard-compliance-audit.html', stats=stats, user={'name': 'User', 'role': 'admin'})
    except Exception as e:
        logger.error(f"Error loading compliance audit dashboard: {e}")
        # Return dashboard with empty stats if DynamoDB not available
        return render_template('dashboard-compliance-audit.html', stats={
            'total_assessments': 0,
            'total_findings': 0,
            'compliant': 0,
            'non_compliant': 0,
            'avg_compliance_score': 0,
            'accounts_scanned': 0,
            'recent_assessments': [],
            'chart_months': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
            'chart_scores': [0, 0, 0, 0, 0, 0]
        }, user={'name': 'User', 'role': 'admin'})

@app.route('/reports')
def reports():
    """List all audit reports"""
    try:
        reports = db_service.list_audit_reports()
        return render_template('reports.html', reports=reports, user={'name': 'User', 'role': 'admin'})
    except Exception as e:
        logger.error(f"Error loading reports: {e}")
        return render_template('reports.html', reports=[], user={'name': 'User', 'role': 'admin'})

@app.route('/audit-modes')
def audit_modes():
    """Serve audit mode selection page - main landing page"""
    return render_template('audit-modes.html')

@app.route('/security-checks')
def security_checks():
    """Serve security checks audit page"""
    return render_template('index.html')

@app.route('/compliance-audit')
def compliance_audit_page():
    """Serve compliance audit page"""
    return render_template('compliance-audit.html')



@app.route('/api/audit-modes', methods=['GET'])
def get_audit_modes():
    """Get available audit modes"""
    return jsonify({
        'modes': [
            {
                'id': 'security_checks',
                'name': 'Security Checks',
                'description': 'Run custom security checks across multiple regions',
                'icon': 'fa-shield-alt',
                'features': [
                    'Multi-region scanning (up to 3 regions)',
                    'Custom check selection',
                    'PDF report generation',
                    'S3 integration'
                ]
            },
            {
                'id': 'compliance_audit',
                'name': 'Compliance Audit',
                'description': 'AWS Audit Manager-based compliance assessments',
                'icon': 'fa-certificate',
                'features': [
                    'AWS Audit Manager integration',
                    'Framework-based assessments',
                    'Compliance scoring',
                    'Evidence tracking',
                    'Assessment management'
                ]
            }
        ]
    }), 200

@app.route('/api/create-tables', methods=['POST'])
def create_tables():
    """Create DynamoDB tables"""
    try:
        success = db_service.create_tables()
        if success:
            return jsonify({'success': True, 'message': 'DynamoDB tables created successfully'}), 200
        else:
            return jsonify({'success': False, 'message': 'Failed to create tables'}), 500
    except Exception as e:
        logger.error(f"Error creating tables: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'aws-security-audit'}), 200

@app.route('/api/compliance/assessments', methods=['GET'])
def get_compliance_assessments():
    """Get AWS Audit Manager assessments"""
    try:
        # Get credentials from session or request
        account_id = request.args.get('accountId')
        role_name = request.args.get('roleName', 'SecurityAuditRole')
        external_id = request.args.get('externalId')
        region = request.args.get('region', 'us-east-1')
        
        if not all([account_id, external_id]):
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # Assume role
        try:
            credentials = iam_role_manager.assume_role(
                account_id=account_id,
                role_name=role_name,
                external_id=external_id,
                region=region
            )
        except Exception as e:
            logger.error(f"Role assumption failed: {str(e)}")
            return jsonify({'error': f'Failed to assume role: {str(e)}'}), 403
        
        # Initialize Audit Manager service
        audit_manager = AuditManagerService(region=region, credentials=credentials)
        
        # Get assessments
        assessments = audit_manager.get_assessments()
        frameworks = audit_manager.get_compliance_frameworks()
        
        return jsonify({
            'success': True,
            'assessments': assessments,
            'frameworks': frameworks
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching assessments: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/setup/audit-manager', methods=['POST'])
def setup_audit_manager():
    """Setup AWS Audit Manager prerequisites automatically"""
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['accountId', 'roleName', 'externalId', 'region']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        account_id = data['accountId']
        role_name = data['roleName']
        external_id = data['externalId']
        region = data['region']
        
        logger.info(f"Setting up AWS Audit Manager for account {account_id}")
        
        # Assume role
        try:
            credentials = iam_role_manager.assume_role(
                account_id=account_id,
                role_name=role_name,
                external_id=external_id,
                region=region
            )
        except Exception as e:
            logger.error(f"Role assumption failed: {str(e)}")
            return jsonify({'error': f'Failed to assume role: {str(e)}'}), 403
        
        # Run setup
        setup = AuditManagerSetup(account_id=account_id, region=region, credentials=credentials)
        results = setup.setup_all()
        
        if results['success']:
            logger.info(f"✅ AWS Audit Manager setup completed for account {account_id}")
            return jsonify({
                'success': True,
                'message': 'AWS Audit Manager setup completed successfully',
                'steps': results['steps']
            }), 200
        else:
            logger.warning(f"⚠️ AWS Audit Manager setup completed with errors: {results['errors']}")
            return jsonify({
                'success': False,
                'message': 'Setup completed with some errors',
                'steps': results['steps'],
                'errors': results['errors']
            }), 200
    
    except Exception as e:
        logger.error(f"Setup failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/audit/compliance', methods=['POST'])
def run_compliance_audit():
    """Run compliance audit using AWS Audit Manager"""
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['accountId', 'roleName', 'externalId', 'region']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Create config
        config = ComplianceAuditConfig(
            account_id=data['accountId'],
            role_name=data['roleName'],
            external_id=data['externalId'],
            region=data['region'],
            framework_id=data.get('frameworkId'),
            assessment_id=data.get('assessmentId'),
            create_new_assessment=data.get('createNewAssessment', True),
            assessment_name=data.get('assessmentName', f"Audit-{utcnow().strftime('%Y%m%d%H%M%S')}"),
            s3_bucket=data.get('s3Bucket')
        )
        
        # Validate config
        is_valid, error_msg = mode_validator.validate_compliance_audit_config(config)
        if not is_valid:
            logger.warning(f"Invalid compliance audit config: {error_msg}")
            return jsonify({'error': error_msg}), 400
        
        logger.info(f"Starting compliance audit for account {config.account_id}")
        
        # Run compliance audit
        results = compliance_engine.run_compliance_audit(config)
        
        if results['success']:
            # Save to DynamoDB
            try:
                import uuid
                report_id = str(uuid.uuid4())
                report_data = {
                    'report_id': report_id,
                    'timestamp': int(utcnow().timestamp()),
                    'account_id': config.account_id,
                    'region': config.region,
                    'scan_date': utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                    'audit_mode': 'compliance_audit',
                    'assessment_id': results.get('assessment_id'),
                    'total_findings': results.get('summary', {}).get('total_findings', 0),
                    'compliance_percentage': results.get('summary', {}).get('compliance_percentage', 0),
                    'compliant': results.get('summary', {}).get('compliant', 0),
                    'non_compliant': results.get('summary', {}).get('non_compliant', 0)
                }
                db_service.save_audit_report(report_data)
                logger.info(f"Saved compliance audit report to DynamoDB: {report_id}")
            except Exception as e:
                logger.warning(f"Failed to save report to DynamoDB: {e}")
            
            return jsonify(results), 200
        else:
            return jsonify(results), 500
    
    except Exception as e:
        logger.error(f"Compliance audit failed: {str(e)}")
        return jsonify({'error': str(e), 'audit_mode': 'compliance_audit'}), 500

@app.route('/api/compliance/assessment/<assessment_id>', methods=['GET'])
def get_assessment_details(assessment_id):
    """Get detailed compliance assessment information"""
    try:
        account_id = request.args.get('accountId')
        role_name = request.args.get('roleName', 'SecurityAuditRole')
        external_id = request.args.get('externalId')
        region = request.args.get('region', 'us-east-1')
        
        if not all([account_id, external_id]):
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # Assume role
        credentials = iam_role_manager.assume_role(
            account_id=account_id,
            role_name=role_name,
            external_id=external_id,
            region=region
        )
        
        # Initialize Audit Manager service
        audit_manager = AuditManagerService(region=region, credentials=credentials)
        
        # Get assessment details
        details = audit_manager.get_assessment_details(assessment_id)
        findings = audit_manager.get_assessment_findings(assessment_id)
        summary = audit_manager.get_compliance_summary(assessment_id)
        
        return jsonify({
            'success': True,
            'assessment': details,
            'findings': findings,
            'summary': summary
        }), 200
    
    except Exception as e:
        logger.error(f"Error fetching assessment details: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/checks', methods=['GET'])
def get_available_checks():
    """Return categorized list of security checks with compliance mappings"""
    checks = {
        'Network Security': [
            {'id': 'EC2_SG_OPEN_0_0_0_0', 'name': 'Open Security Groups', 'severity': 'Critical', 'description': 'Security groups allowing 0.0.0.0/0 access', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS', 'NIST']},
            {'id': 'EC2_NO_IMDSV2', 'name': 'IMDSv2 Not Enforced', 'severity': 'High', 'description': 'EC2 instances not using IMDSv2', 'compliance': ['CIS', 'NIST']},
        ],
        'Storage Security': [
            {'id': 'S3_PUBLIC_BUCKET', 'name': 'Public S3 Buckets', 'severity': 'Critical', 'description': 'S3 buckets with public access', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS', 'GDPR']},
            {'id': 'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS', 'name': 'Excessive S3 Policies', 'severity': 'High', 'description': 'S3 bucket policies with wildcard permissions', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
            {'id': 'EBS_UNENCRYPTED', 'name': 'Unencrypted EBS Volumes', 'severity': 'High', 'description': 'EBS volumes without encryption', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS', 'NIST']},
            {'id': 'EBS_SNAPSHOT_UNENCRYPTED', 'name': 'Unencrypted EBS Snapshots', 'severity': 'High', 'description': 'EBS snapshots without encryption', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
            {'id': 'DYNAMODB_UNENCRYPTED', 'name': 'Unencrypted DynamoDB Tables', 'severity': 'High', 'description': 'DynamoDB tables without encryption at rest', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
        ],
        'Database Security': [
            {'id': 'RDS_PUBLIC_ACCESS', 'name': 'Public RDS Instances', 'severity': 'Critical', 'description': 'RDS instances publicly accessible', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
            {'id': 'RDS_UNENCRYPTED', 'name': 'Unencrypted RDS', 'severity': 'High', 'description': 'RDS instances without encryption', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS', 'GDPR']},
            {'id': 'AURORA_UNENCRYPTED', 'name': 'Unencrypted Aurora', 'severity': 'High', 'description': 'Aurora clusters without encryption', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS', 'GDPR']},
            {'id': 'RDS_AURORA_BACKUP_UNENCRYPTED', 'name': 'Unencrypted Backups', 'severity': 'Critical', 'description': 'Database backups without encryption', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
        ],
        'Identity & Access': [
            {'id': 'ROOT_MFA_DISABLED', 'name': 'Root MFA Disabled', 'severity': 'Critical', 'description': 'Root account without MFA enabled', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS', 'NIST']},
            {'id': 'IAM_USER_INACTIVE', 'name': 'Inactive IAM Users', 'severity': 'Critical', 'description': 'Users inactive for 60+ days', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
            {'id': 'IAM_ACCESS_KEY_UNUSED', 'name': 'Unused Access Keys', 'severity': 'High', 'description': 'Access keys unused for 90+ days', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
            {'id': 'IAM_ROLE_UNUSED', 'name': 'Unused IAM Roles', 'severity': 'Low', 'description': 'Roles unused for 120+ days', 'compliance': ['CIS']},
        ],
        'Compute Security': [
            {'id': 'AMI_UNENCRYPTED', 'name': 'Unencrypted AMIs', 'severity': 'High', 'description': 'AMIs with unencrypted snapshots', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
            {'id': 'EC2_UNUSED_KEY_PAIR', 'name': 'Unused Key Pairs', 'severity': 'Medium', 'description': 'EC2 key pairs not attached to instances', 'compliance': ['CIS']},
            {'id': 'ECS_ENCRYPTION_ISSUE', 'name': 'ECS Encryption Issues', 'severity': 'High', 'description': 'ECS tasks with encryption concerns', 'compliance': ['PCI-DSS', 'HIPAA']},
        ],
        'Application Security': [
            {'id': 'API_GW_LOG_UNENCRYPTED', 'name': 'Unencrypted API Logs', 'severity': 'High', 'description': 'API Gateway logs without KMS encryption', 'compliance': ['PCI-DSS', 'HIPAA']},
            {'id': 'CLOUDFRONT_ENCRYPTION_ISSUE', 'name': 'CloudFront HTTPS', 'severity': 'High', 'description': 'CloudFront not enforcing HTTPS', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
        ],
        'Secrets & Keys': [
            {'id': 'UNUSED_KMS_KEYS', 'name': 'Unused KMS Keys', 'severity': 'Low', 'description': 'Disabled or unused KMS keys', 'compliance': ['CIS']},
            {'id': 'UNUSED_SECRETS', 'name': 'Unused Secrets', 'severity': 'Medium', 'description': 'Secrets not accessed for 90+ days', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
            {'id': 'SECRETS_UNENCRYPTED', 'name': 'Secrets Without Custom KMS', 'severity': 'Low', 'description': 'Secrets Manager secrets without custom KMS encryption (Informational)', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
            {'id': 'SSM_PARAMETERS_UNENCRYPTED', 'name': 'Unencrypted SSM Parameters', 'severity': 'Low', 'description': 'SSM Parameter Store parameters not using SecureString (Informational)', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
            {'id': 'PARAMETER_STORE_ISSUE', 'name': 'Stale Parameters', 'severity': 'Medium', 'description': 'Parameters not modified for 60+ days', 'compliance': ['CIS']},
        ],
        'Backup & Recovery': [
            {'id': 'BACKUP_VAULT_UNENCRYPTED', 'name': 'Unencrypted Backup Vaults', 'severity': 'High', 'description': 'AWS Backup vaults without KMS encryption', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
        ],
        'Serverless Security': [
            {'id': 'LAMBDA_PUBLIC_ACCESS', 'name': 'Public Lambda Functions', 'severity': 'Critical', 'description': 'Lambda functions with public access policies', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
            {'id': 'SNS_UNENCRYPTED', 'name': 'Unencrypted SNS Topics', 'severity': 'High', 'description': 'SNS topics without KMS encryption', 'compliance': ['PCI-DSS', 'HIPAA']},
            {'id': 'SQS_UNENCRYPTED', 'name': 'Unencrypted SQS Queues', 'severity': 'High', 'description': 'SQS queues without KMS encryption', 'compliance': ['PCI-DSS', 'HIPAA']},
        ],
        'Monitoring & Logging': [
            {'id': 'CLOUDTRAIL_ISSUES', 'name': 'CloudTrail Issues', 'severity': 'Critical', 'description': 'CloudTrail logging disabled or not encrypted', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS', 'NIST']},
            {'id': 'VPC_NO_FLOW_LOGS', 'name': 'VPC Flow Logs Disabled', 'severity': 'Medium', 'description': 'VPCs without flow logs enabled', 'compliance': ['PCI-DSS', 'CIS']},
            {'id': 'VPC_LOGS_UNENCRYPTED', 'name': 'VPC Flow Logs Unencrypted', 'severity': 'Medium', 'description': 'VPC flow logs without KMS encryption', 'compliance': ['PCI-DSS', 'CIS', 'NIST']},
            {'id': 'ELB_NO_LOGGING', 'name': 'ELB Access Logs Disabled', 'severity': 'Medium', 'description': 'Load balancers without access logging', 'compliance': ['PCI-DSS', 'CIS']},
        ],
        'Security Services': [
            {'id': 'GUARDDUTY_DISABLED', 'name': 'GuardDuty Disabled', 'severity': 'High', 'description': 'Amazon GuardDuty threat detection not enabled', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS', 'NIST']},
            {'id': 'SECURITYHUB_DISABLED', 'name': 'Security Hub Disabled', 'severity': 'Medium', 'description': 'AWS Security Hub not enabled', 'compliance': ['CIS', 'NIST']},
            {'id': 'INSPECTOR_DISABLED', 'name': 'Inspector Disabled', 'severity': 'Medium', 'description': 'Amazon Inspector vulnerability scanning not enabled', 'compliance': ['CIS', 'NIST']},
        ],
        'Container Security': [
            {'id': 'ECR_TAG_MUTABLE', 'name': 'ECR Tag Mutable', 'severity': 'Medium', 'description': 'ECR repositories without tag immutability enabled', 'compliance': ['PCI-DSS', 'CIS']},
            {'id': 'ECR_SCAN_ON_PUSH_DISABLED', 'name': 'ECR Scan on Push Disabled', 'severity': 'High', 'description': 'ECR repositories without scan on push enabled', 'compliance': ['CIS', 'NIST']},
            {'id': 'EKS_CLUSTER_LOGGING_DISABLED', 'name': 'EKS Cluster Logging Disabled', 'severity': 'Medium', 'description': 'EKS clusters without logging enabled', 'compliance': ['CIS', 'PCI-DSS']},
            {'id': 'EKS_PUBLIC_ENDPOINT', 'name': 'EKS Public Endpoint', 'severity': 'High', 'description': 'EKS clusters with public API endpoint', 'compliance': ['CIS', 'HIPAA']},
        ],
        'Data Protection': [
            {'id': 'GLACIER_VAULT_UNENCRYPTED', 'name': 'Unencrypted Glacier Vaults', 'severity': 'High', 'description': 'Glacier vaults without encryption', 'compliance': ['PCI-DSS', 'HIPAA']},
            {'id': 'REDSHIFT_UNENCRYPTED', 'name': 'Unencrypted Redshift Clusters', 'severity': 'Critical', 'description': 'Redshift clusters without encryption at rest', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
            {'id': 'REDSHIFT_PUBLIC_ACCESS', 'name': 'Public Redshift Clusters', 'severity': 'Critical', 'description': 'Redshift clusters publicly accessible', 'compliance': ['PCI-DSS', 'HIPAA', 'CIS']},
            {'id': 'ELASTICACHE_UNENCRYPTED', 'name': 'Unencrypted ElastiCache', 'severity': 'High', 'description': 'ElastiCache clusters without encryption', 'compliance': ['PCI-DSS', 'HIPAA']},
        ]
    }
    return jsonify({'checks': checks}), 200

@app.route('/api/audit', methods=['POST'])
def run_audit():
    """Run security audit with specified checks - supports single or multiple regions"""
    try:
        data = request.json
        
        # Validate audit request
        is_valid, error_msg = validator.validate_audit_request(data)
        if not is_valid:
            logger.warning(f"Invalid audit request: {error_msg}")
            return jsonify({'error': error_msg}), 400
        
        account_id = data['accountId']
        
        regions = data['regions']
        
        role_name = data['roleName']
        external_id = data['externalId']
        selected_checks = data['selectedChecks']
        
        logger.info(f"Starting multi-region audit for account {account_id} in regions: {regions}")
        
        # Assume role once (valid for all regions)
        try:
            credentials_dict = iam_role_manager.assume_role(
                account_id=account_id,
                role_name=role_name,
                external_id=external_id,
                region=regions[0]
            )
            credentials = credentials_dict
        except Exception as e:
            logger.error(f"Role assumption failed: {str(e)}")
            return jsonify({'error': f'Failed to assume role: {str(e)}'}), 403
        
        # Generate timestamp for report naming
        timestamp = utcnow().strftime('%Y%m%d%H%M%S')
        
        # S3 bucket name - use provided or generate default (one bucket per account)
        s3_bucket = data.get('s3Bucket', '').strip()
        if not s3_bucket:
            s3_bucket = f'aws-security-audit-{account_id}'.lower()
        
        logger.info(f"Using S3 bucket: {s3_bucket}")
        
        logger.info("Successfully obtained credentials for audited account")
        
        # Run audits for all regions
        all_results = {}
        all_findings = []
        
        for region in regions:
            logger.info(f"Running audit for region: {region}")
            
            try:
                # Initialize audit for this region with assumed role credentials
                audit = AWSecurityAudit(region, credentials)
                
                # Run selected checks
                check_methods = {
                    'EC2_SG_OPEN_0_0_0_0': audit.check_ec2_security_groups,
                    'S3_PUBLIC_BUCKET': audit.check_s3_public_buckets,
                    'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS': audit.check_s3_bucket_policies_excessive_permissions,
                    'IAM_USER_INACTIVE': audit.check_iam_users_inactive,
                    'IAM_ACCESS_KEY_UNUSED': audit.check_iam_access_keys_unused,
                    'EBS_UNENCRYPTED': audit.check_ebs_encryption,
                    'EBS_SNAPSHOT_UNENCRYPTED': audit.check_ebs_snapshot_encryption,
                    'DYNAMODB_UNENCRYPTED': audit.check_dynamodb_encryption,
                    'RDS_UNENCRYPTED': audit.check_rds_encryption,
                    'RDS_PUBLIC_ACCESS': audit.check_rds_public_access,
                    'AURORA_UNENCRYPTED': audit.check_aurora_encryption,
                    'ROOT_MFA_DISABLED': audit.check_root_account_mfa,
                    'IAM_ROLE_UNUSED': audit.check_iam_roles_unused,
                    'BACKUP_VAULT_UNENCRYPTED': audit.check_backup_vaults_encryption,
                    'EC2_NO_IMDSV2': audit.check_ec2_imdsv2,
                    'EC2_UNUSED_KEY_PAIR': audit.check_unused_key_pairs,
                    'AMI_UNENCRYPTED': audit.check_ami_encryption,
                    'ECS_ENCRYPTION_ISSUE': audit.check_ecs_encryption_issues,
                    'API_GW_LOG_UNENCRYPTED': audit.check_api_gateway_log_encryption,
                    'CLOUDFRONT_ENCRYPTION_ISSUE': audit.check_cloudfront_encryption,
                    'RDS_AURORA_BACKUP_UNENCRYPTED': audit.check_rds_aurora_backups_encrypted,
                    'UNUSED_KMS_KEYS': audit.check_unused_kms_keys,
                    'UNUSED_SECRETS': audit.check_unused_secrets,
                    'SECRETS_UNENCRYPTED': audit.check_secrets_encryption,
                    'SSM_PARAMETERS_UNENCRYPTED': audit.check_ssm_parameters_encryption,
                    'PARAMETER_STORE_ISSUE': audit.check_parameter_store,
                    'VPC_NO_FLOW_LOGS': audit.check_vpc_flow_logs,
                    'LAMBDA_PUBLIC_ACCESS': audit.check_lambda_public_access,
                    'ELB_NO_LOGGING': audit.check_elb_logging,
                    'SNS_UNENCRYPTED': audit.check_sns_topic_encryption,
                    'SQS_UNENCRYPTED': audit.check_sqs_queue_encryption,
                    'CLOUDTRAIL_ISSUES': audit.check_cloudtrail_logging
                }
                
                report = {}
                for check_id in selected_checks:
                    if check_id in check_methods:
                        try:
                            report[check_id] = check_methods[check_id]()
                        except Exception as e:
                            logger.error(f"Check {check_id} failed in {region}: {str(e)}")
                            report[check_id] = []
                
                # Score findings for this region
                scored_report = audit.score_findings(report)
                all_results[region] = scored_report
                all_findings.extend(scored_report)
                
                logger.info(f"✅ Audit completed for {region}: {sum(entry['count'] for entry in scored_report)} findings")
                
            except Exception as e:
                logger.error(f"❌ Audit failed for region {region}: {str(e)}")
                all_results[region] = []
        
        # Calculate combined summary across all regions
        summary = {
            'total': sum(entry['count'] for entry in all_findings),
            'critical': sum(entry['count'] for entry in all_findings if entry['severity'] == 3),
            'high': sum(entry['count'] for entry in all_findings if entry['severity'] == 2),
            'medium': sum(entry['count'] for entry in all_findings if entry['severity'] == 1),
            'low': sum(entry['count'] for entry in all_findings if entry['severity'] == 0),
            'regions_audited': len(regions),
            'regions': regions
        }
        
        logger.info(f"Multi-region audit completed: {summary['total']} findings across {len(regions)} regions")
        
        # Save report to DynamoDB for dashboard tracking
        try:
            import uuid
            report_id = str(uuid.uuid4())
            report_data = {
                'report_id': report_id,
                'timestamp': int(utcnow().timestamp()),
                'account_id': account_id,
                'region': ', '.join(regions),
                'scan_date': utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'total_findings': summary['total'],
                'critical_findings': summary['critical'],
                'high_findings': summary['high'],
                'medium_findings': summary['medium'],
                'low_findings': summary['low'],
                'regions_audited': len(regions)
            }
            db_service.save_audit_report(report_data)
            logger.info(f"Saved report to DynamoDB: {report_id}")
        except Exception as e:
            logger.warning(f"Failed to save report to DynamoDB: {e}")
        
        # Generate PDF report and upload to customer's S3 bucket
        logger.info(f"Generating PDF report for all regions...")
        primary_region = regions[0]
        pdf_buffer = create_pdf_report(all_findings, primary_region, credentials=credentials)
        
        # S3 bucket name - use provided or generate default (one bucket per account)
        s3_bucket = data.get('s3Bucket', '').strip()
        if not s3_bucket:
            s3_bucket = f'aws-security-audit-{account_id}'.lower()
        
        logger.info(f"Creating S3 bucket in customer account: {s3_bucket}")
        create_s3_bucket_if_not_exists(s3_bucket, primary_region, credentials)
        
        # Upload PDF to customer's S3 bucket
        pdf_timestamp = utcnow().strftime('%Y%m%dT%H%M%SZ')
        object_key, presigned_url = upload_pdf_to_s3(pdf_buffer, primary_region, s3_bucket, pdf_timestamp, credentials=credentials)
        
        logger.info(f"PDF uploaded to customer's S3: {object_key}")
        
        return jsonify({
            'success': True,
            'summary': summary,
            'findings': all_findings,
            'findings_by_region': all_results,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'report': {
                's3_bucket': s3_bucket,
                's3_key': object_key,
                'presigned_url': presigned_url,
                'expires_in': 3600
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Audit failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/report/download', methods=['POST'])
def download_report():
    """Generate and download PDF report on-the-fly"""
    try:
        data = request.json
        
        # Validate required fields
        required_fields = ['accountId', 'roleName', 'externalId', 'selectedChecks']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        account_id = data['accountId']
        role_name = data['roleName']
        external_id = data['externalId']
        selected_checks = data['selectedChecks']
        regions = data.get('regions', ['us-east-1'])
        
        if isinstance(regions, str):
            regions = [regions]
        
        logger.info(f"Generating PDF report for account {account_id}")
        
        # Assume role
        credentials = iam_role_manager.assume_role(
            account_id=account_id,
            role_name=role_name,
            external_id=external_id,
            region=regions[0]
        )
        
        # Run audits for all regions
        all_findings = []
        for region in regions:
            try:
                audit = AWSecurityAudit(region, credentials)
                
                check_methods = {
                    'EC2_SG_OPEN_0_0_0_0': audit.check_ec2_security_groups,
                    'S3_PUBLIC_BUCKET': audit.check_s3_public_buckets,
                    'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS': audit.check_s3_bucket_policies_excessive_permissions,
                    'IAM_USER_INACTIVE': audit.check_iam_users_inactive,
                    'IAM_ACCESS_KEY_UNUSED': audit.check_iam_access_keys_unused,
                    'EBS_UNENCRYPTED': audit.check_ebs_encryption,
                    'RDS_UNENCRYPTED': audit.check_rds_encryption,
                    'RDS_PUBLIC_ACCESS': audit.check_rds_public_access,
                    'AURORA_UNENCRYPTED': audit.check_aurora_encryption,
                    'ROOT_MFA_DISABLED': audit.check_root_account_mfa,
                    'IAM_ROLE_UNUSED': audit.check_iam_roles_unused,
                    'BACKUP_VAULT_UNENCRYPTED': audit.check_backup_vaults_encryption,
                    'EC2_NO_IMDSV2': audit.check_ec2_imdsv2,
                    'EC2_UNUSED_KEY_PAIR': audit.check_unused_key_pairs,
                    'AMI_UNENCRYPTED': audit.check_ami_encryption,
                    'ECS_ENCRYPTION_ISSUE': audit.check_ecs_encryption_issues,
                    'API_GW_LOG_UNENCRYPTED': audit.check_api_gateway_log_encryption,
                    'CLOUDFRONT_ENCRYPTION_ISSUE': audit.check_cloudfront_encryption,
                    'RDS_AURORA_BACKUP_UNENCRYPTED': audit.check_rds_aurora_backups_encrypted,
                    'UNUSED_KMS_KEYS': audit.check_unused_kms_keys,
                    'UNUSED_SECRETS': audit.check_unused_secrets,
                    'SECRETS_UNENCRYPTED': audit.check_secrets_encryption,
                    'SSM_PARAMETERS_UNENCRYPTED': audit.check_ssm_parameters_encryption,
                    'PARAMETER_STORE_ISSUE': audit.check_parameter_store,
                    'VPC_NO_FLOW_LOGS': audit.check_vpc_flow_logs,
                    'LAMBDA_PUBLIC_ACCESS': audit.check_lambda_public_access,
                    'ELB_NO_LOGGING': audit.check_elb_logging,
                    'SNS_UNENCRYPTED': audit.check_sns_topic_encryption,
                    'SQS_UNENCRYPTED': audit.check_sqs_queue_encryption,
                    'CLOUDTRAIL_ISSUES': audit.check_cloudtrail_logging
                }
                
                report = {}
                for check_id in selected_checks:
                    if check_id in check_methods:
                        try:
                            report[check_id] = check_methods[check_id]()
                        except Exception as e:
                            logger.error(f"Check {check_id} failed: {str(e)}")
                            report[check_id] = []
                
                scored_report = audit.score_findings(report)
                all_findings.extend(scored_report)
                
            except Exception as e:
                logger.error(f"Audit failed for region {region}: {str(e)}")
        
        # Generate PDF
        pdf_buffer = create_pdf_report(all_findings, regions[0])
        
        # Return PDF as file download
        pdf_buffer.seek(0)
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'aws_audit_{utcnow().strftime("%Y%m%d_%H%M%S")}.pdf'
        )
        
    except Exception as e:
        logger.error(f"PDF generation failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
