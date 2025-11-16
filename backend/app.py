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
        
        sts_client = boto3.client('sts')
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        
        logger.info(f"Assuming role: {role_arn} with External ID")
        
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='SecurityAuditSession',
            ExternalId=external_id
        )
        
        credentials = response['Credentials']
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
    """Return list of available security checks"""
    checks = [
        {'id': 'EC2_SG_OPEN_0_0_0_0', 'name': 'EC2 Security Groups Open to Internet', 'severity': 'Critical'},
        {'id': 'S3_PUBLIC_BUCKET', 'name': 'S3 Public Buckets', 'severity': 'Critical'},
        {'id': 'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS', 'name': 'S3 Excessive Bucket Policies', 'severity': 'High'},
        {'id': 'IAM_USER_INACTIVE', 'name': 'IAM Inactive Users', 'severity': 'Low'},
        {'id': 'IAM_ACCESS_KEY_UNUSED', 'name': 'IAM Unused Access Keys', 'severity': 'Low'},
        {'id': 'EBS_UNENCRYPTED', 'name': 'EBS Unencrypted Volumes', 'severity': 'High'},
        {'id': 'RDS_UNENCRYPTED', 'name': 'RDS Unencrypted Instances', 'severity': 'High'},
        {'id': 'AURORA_UNENCRYPTED', 'name': 'Aurora Unencrypted Clusters', 'severity': 'High'},
        {'id': 'IAM_ROLE_UNUSED', 'name': 'IAM Unused Roles', 'severity': 'Low'},
        {'id': 'BACKUP_VAULT_UNENCRYPTED', 'name': 'Backup Vault Unencrypted', 'severity': 'High'},
        {'id': 'EC2_NO_IMDSV2', 'name': 'EC2 Not Using IMDSv2', 'severity': 'High'},
        {'id': 'EC2_UNUSED_KEY_PAIR', 'name': 'EC2 Unused Key Pairs', 'severity': 'Low'},
        {'id': 'ECS_ENCRYPTION_ISSUE', 'name': 'ECS Encryption Issues', 'severity': 'High'},
        {'id': 'API_GW_LOG_UNENCRYPTED', 'name': 'API Gateway Logs Unencrypted', 'severity': 'High'},
        {'id': 'CLOUDFRONT_ENCRYPTION_ISSUE', 'name': 'CloudFront HTTPS Issues', 'severity': 'High'},
        {'id': 'RDS_AURORA_BACKUP_UNENCRYPTED', 'name': 'RDS/Aurora Backup Unencrypted', 'severity': 'Critical'},
        {'id': 'UNUSED_KMS_KEYS', 'name': 'Unused KMS Keys', 'severity': 'Low'},
        {'id': 'UNUSED_SECRETS', 'name': 'Unused Secrets', 'severity': 'Low'},
        {'id': 'PARAMETER_STORE_ISSUE', 'name': 'Parameter Store Unused Parameters', 'severity': 'Low'}
    ]
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
        
        # Generate timestamp for default bucket name
        timestamp = utcnow().strftime('%Y%m%d%H%M%S')
        
        # S3 bucket name - use provided or generate default
        s3_bucket = data.get('s3Bucket', '').strip()
        if not s3_bucket:
            s3_bucket = f'aws-security-audit-{account_id}-{timestamp}'.lower()
        
        logger.info(f"Using S3 bucket: {s3_bucket}")
        
        # Assume role once (valid for all regions)
        credentials = assume_role(account_id, role_name, external_id, regions[0])
        
        # Configure boto3 with assumed role credentials
        os.environ['AWS_ACCESS_KEY_ID'] = credentials['aws_access_key_id']
        os.environ['AWS_SECRET_ACCESS_KEY'] = credentials['aws_secret_access_key']
        os.environ['AWS_SESSION_TOKEN'] = credentials['aws_session_token']
        
        # Run audits for all regions
        all_results = {}
        all_findings = []
        
        for region in regions:
            logger.info(f"Running audit for region: {region}")
            
            try:
                # Initialize audit for this region
                audit = AWSecurityAudit(region)
                
                # Run selected checks
                check_methods = {
                    'EC2_SG_OPEN_0_0_0_0': audit.check_ec2_security_groups,
                    'S3_PUBLIC_BUCKET': audit.check_s3_public_buckets,
                    'S3_BUCKET_POLICY_EXCESSIVE_PERMISSIONS': audit.check_s3_bucket_policies_excessive_permissions,
                    'IAM_USER_INACTIVE': audit.check_iam_users_inactive,
                    'IAM_ACCESS_KEY_UNUSED': audit.check_iam_access_keys_unused,
                    'EBS_UNENCRYPTED': audit.check_ebs_encryption,
                    'RDS_UNENCRYPTED': audit.check_rds_encryption,
                    'AURORA_UNENCRYPTED': audit.check_aurora_encryption,
                    'IAM_ROLE_UNUSED': audit.check_iam_roles_unused,
                    'BACKUP_VAULT_UNENCRYPTED': audit.check_backup_vaults_encryption,
                    'EC2_NO_IMDSV2': audit.check_ec2_imdsv2,
                    'EC2_UNUSED_KEY_PAIR': audit.check_unused_key_pairs,
                    'ECS_ENCRYPTION_ISSUE': audit.check_ecs_encryption_issues,
                    'API_GW_LOG_UNENCRYPTED': audit.check_api_gateway_log_encryption,
                    'CLOUDFRONT_ENCRYPTION_ISSUE': audit.check_cloudfront_encryption,
                    'RDS_AURORA_BACKUP_UNENCRYPTED': audit.check_rds_aurora_backups_encrypted,
                    'UNUSED_KMS_KEYS': audit.check_unused_kms_keys,
                    'UNUSED_SECRETS': audit.check_unused_secrets,
                    'PARAMETER_STORE_ISSUE': audit.check_parameter_store
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
        
        # Generate PDF and upload to S3
        logger.info("Generating PDF report for all regions...")
        
        # Use first region for PDF naming
        primary_region = regions[0]
        pdf_buffer = create_pdf_report(all_findings, primary_region)
        
        # Create S3 bucket if needed
        logger.info(f"Creating S3 bucket: {s3_bucket}")
        create_s3_bucket_if_not_exists(s3_bucket, primary_region)
        
        # Upload PDF to S3
        pdf_timestamp = utcnow().strftime('%Y%m%dT%H%M%SZ')
        object_key, presigned_url = upload_pdf_to_s3(pdf_buffer, primary_region, s3_bucket, pdf_timestamp)
        
        # Save metadata for future comparisons
        save_report_metadata(s3_bucket, primary_region, all_findings, timestamp)
        
        logger.info(f"PDF uploaded to S3: {object_key}")
        
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

@app.route('/api/report/download', methods=['GET'])
def download_report():
    """Redirect to S3 presigned URL for PDF download"""
    try:
        presigned_url = request.args.get('url')
        
        if not presigned_url:
            return jsonify({'error': 'Missing presigned URL'}), 400
        
        # Redirect to S3 presigned URL
        return redirect(presigned_url)
        
    except Exception as e:
        logger.error(f"Download redirect failed: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port, debug=False)
