"""
Flask Backend for AWS Security Audit Application
Provides REST API for running security audits with cross-account role assumption
"""

import os
import json
import boto3
from flask import Flask, request, jsonify, render_template, redirect
from datetime import datetime, timezone
import logging
from io import BytesIO
import sys

# Import the security audit class from same directory
from .sa import (
    AWSecurityAudit, 
    create_pdf_report, 
    SEVERITY_MAP,
    upload_pdf_to_s3,
    create_s3_bucket_if_not_exists,
    save_report_metadata,
    utcnow
)

# Configure Flask with templates
app = Flask(__name__, template_folder='../templates')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def assume_role(account_id, role_name, external_id, region):
    """Assume cross-account IAM role with mandatory External ID"""
    try:
        if not external_id:
            raise ValueError("External ID is required for cross-account role assumption")
        
        sts_client = boto3.client('sts', region_name=region)
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        
        logger.info(f"Assuming role: {role_arn} with External ID")
        
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='SecurityAuditSession',
            ExternalId=external_id
        )
        
        credentials = response['Credentials']
        logger.info(f"Successfully assumed role: {role_arn}")
        return {
            'aws_access_key_id': credentials['AccessKeyId'],
            'aws_secret_access_key': credentials['SecretAccessKey'],
            'aws_session_token': credentials['SessionToken']
        }
    except Exception as e:
        logger.error(f"Failed to assume role: {str(e)}")
        raise

@app.route('/')
def index():
    """Serve main page"""
    return render_template('index.html')

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'aws-security-audit'}), 200

@app.route('/api/checks', methods=['GET'])
def get_available_checks():
    """Return categorized list of security checks"""
    checks = {
        'Network Security': [
            {'id': 'EC2_SG_OPEN_0_0_0_0', 'name': 'Open Security Groups', 'severity': 'Critical', 'description': 'Security groups allowing 0.0.0.0/0 access'},
            {'id': 'EC2_NO_IMDSV2', 'name': 'IMDSv2 Not Enforced', 'severity': 'High', 'description': 'EC2 instances not using IMDSv2'},
        ],
        'Storage Security': [
            {'id': 'S3_PUBLIC_BUCKET', 'name': 'Public S3 Buckets', 'severity': 'Critical', 'description': 'S3 buckets with public access'},
            {'id': 'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS', 'name': 'Excessive S3 Policies', 'severity': 'High', 'description': 'S3 bucket policies with wildcard permissions'},
            {'id': 'EBS_UNENCRYPTED', 'name': 'Unencrypted EBS Volumes', 'severity': 'High', 'description': 'EBS volumes without encryption'},
        ],
        'Database Security': [
            {'id': 'RDS_PUBLIC_ACCESS', 'name': 'Public RDS Instances', 'severity': 'Critical', 'description': 'RDS instances publicly accessible'},
            {'id': 'RDS_UNENCRYPTED', 'name': 'Unencrypted RDS', 'severity': 'High', 'description': 'RDS instances without encryption'},
            {'id': 'AURORA_UNENCRYPTED', 'name': 'Unencrypted Aurora', 'severity': 'High', 'description': 'Aurora clusters without encryption'},
            {'id': 'RDS_AURORA_BACKUP_UNENCRYPTED', 'name': 'Unencrypted Backups', 'severity': 'Critical', 'description': 'Database backups without encryption'},
        ],
        'Identity & Access': [
            {'id': 'ROOT_MFA_DISABLED', 'name': 'Root MFA Disabled', 'severity': 'Critical', 'description': 'Root account without MFA enabled'},
            {'id': 'IAM_USER_INACTIVE', 'name': 'Inactive IAM Users', 'severity': 'Critical', 'description': 'Users inactive for 60+ days'},
            {'id': 'IAM_ACCESS_KEY_UNUSED', 'name': 'Unused Access Keys', 'severity': 'High', 'description': 'Access keys unused for 90+ days'},
            {'id': 'IAM_ROLE_UNUSED', 'name': 'Unused IAM Roles', 'severity': 'Low', 'description': 'Roles unused for 120+ days'},
        ],
        'Compute Security': [
            {'id': 'AMI_UNENCRYPTED', 'name': 'Unencrypted AMIs', 'severity': 'High', 'description': 'AMIs with unencrypted snapshots'},
            {'id': 'EC2_UNUSED_KEY_PAIR', 'name': 'Unused Key Pairs', 'severity': 'Medium', 'description': 'EC2 key pairs not attached to instances'},
            {'id': 'ECS_ENCRYPTION_ISSUE', 'name': 'ECS Encryption Issues', 'severity': 'High', 'description': 'ECS tasks with encryption concerns'},
        ],
        'Application Security': [
            {'id': 'API_GW_LOG_UNENCRYPTED', 'name': 'Unencrypted API Logs', 'severity': 'High', 'description': 'API Gateway logs without KMS encryption'},
            {'id': 'CLOUDFRONT_ENCRYPTION_ISSUE', 'name': 'CloudFront HTTPS', 'severity': 'High', 'description': 'CloudFront not enforcing HTTPS'},
        ],
        'Secrets & Keys': [
            {'id': 'UNUSED_KMS_KEYS', 'name': 'Unused KMS Keys', 'severity': 'Low', 'description': 'Disabled or unused KMS keys'},
            {'id': 'UNUSED_SECRETS', 'name': 'Unused Secrets', 'severity': 'Medium', 'description': 'Secrets not accessed for 90+ days'},
            {'id': 'PARAMETER_STORE_ISSUE', 'name': 'Stale Parameters', 'severity': 'Medium', 'description': 'Parameters not modified for 60+ days'},
        ],
        'Backup & Recovery': [
            {'id': 'BACKUP_VAULT_UNENCRYPTED', 'name': 'Unencrypted Backup Vaults', 'severity': 'High', 'description': 'AWS Backup vaults without KMS encryption'},
        ],
        'Serverless Security': [
            {'id': 'LAMBDA_PUBLIC_ACCESS', 'name': 'Public Lambda Functions', 'severity': 'Critical', 'description': 'Lambda functions with public access policies'},
            {'id': 'SNS_UNENCRYPTED', 'name': 'Unencrypted SNS Topics', 'severity': 'High', 'description': 'SNS topics without KMS encryption'},
            {'id': 'SQS_UNENCRYPTED', 'name': 'Unencrypted SQS Queues', 'severity': 'High', 'description': 'SQS queues without KMS encryption'},
        ],
        'Monitoring & Logging': [
            {'id': 'CLOUDTRAIL_ISSUES', 'name': 'CloudTrail Issues', 'severity': 'Critical', 'description': 'CloudTrail logging disabled or not encrypted'},
            {'id': 'VPC_NO_FLOW_LOGS', 'name': 'VPC Flow Logs Disabled', 'severity': 'Medium', 'description': 'VPCs without flow logs enabled'},
            {'id': 'ELB_NO_LOGGING', 'name': 'ELB Access Logs Disabled', 'severity': 'Medium', 'description': 'Load balancers without access logging'},
        ]
    }
    return jsonify({'checks': checks}), 200

@app.route('/api/audit', methods=['POST'])
def run_audit():
    """Run security audit with specified checks - supports single or multiple regions"""
    try:
        data = request.json
        
        # Validate required fields - External ID is now mandatory
        required_fields = ['accountId', 'roleName', 'externalId', 'selectedChecks']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        account_id = data['accountId']
        
        # Validate account ID format (12 digits)
        if not account_id.isdigit() or len(account_id) != 12:
            return jsonify({'error': 'Invalid account ID. Must be 12 digits'}), 400
        
        # Support both single region and multiple regions
        regions = data.get('regions', [])
        region = data.get('region', '')
        
        # If single region provided, convert to list
        if region and not regions:
            regions = [region]
        elif not regions:
            return jsonify({'error': 'Missing required field: region or regions'}), 400
        
        # Ensure regions is a list
        if isinstance(regions, str):
            regions = [regions]
        
        # Enforce max 3 regions for performance
        if len(regions) > 3:
            return jsonify({
                'error': 'Maximum 3 regions allowed per audit for optimal performance. Please select up to 3 regions.'
            }), 400
        
        # Valid AWS regions
        valid_regions = [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1', 'eu-north-1',
            'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
            'ap-south-1', 'ca-central-1', 'sa-east-1', 'me-south-1', 'af-south-1'
        ]
        
        # Validate all regions exist
        invalid_regions = [r for r in regions if r not in valid_regions]
        if invalid_regions:
            return jsonify({
                'error': f'Invalid AWS regions: {", ".join(invalid_regions)}. Valid regions: {", ".join(valid_regions)}'
            }), 400
        
        logger.info(f"Validated regions: {regions}")
        logger.info(f"Validated account ID: {account_id}")
        role_name = data['roleName']
        external_id = data['externalId']
        selected_checks = data['selectedChecks']
        
        logger.info(f"Starting multi-region audit for account {account_id} in regions: {regions}")
        
        # Generate timestamp for report naming
        timestamp = utcnow().strftime('%Y%m%d%H%M%S')
        
        # S3 bucket name - use provided or generate default (one bucket per account)
        s3_bucket = data.get('s3Bucket', '').strip()
        if not s3_bucket:
            s3_bucket = f'aws-security-audit-{account_id}'.lower()
        
        logger.info(f"Using S3 bucket: {s3_bucket}")
        
        # Assume role once (valid for all regions)
        credentials = assume_role(account_id, role_name, external_id, regions[0])
        
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
        
        # Generate PDF report and upload to customer's S3 bucket
        logger.info("Generating PDF report for all regions...")
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
        credentials = assume_role(account_id, role_name, external_id, regions[0])
        
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
