"""
DynamoDB Service Module
Handles DynamoDB operations for tracking audit report usage
"""

import boto3
from datetime import datetime
from decimal import Decimal
import json
import logging
import uuid

logger = logging.getLogger(__name__)

class DynamoDBService:
    def __init__(self, region='us-east-1'):
        self.dynamodb = boto3.resource('dynamodb', region_name=region)
        self.region = region
        
        # Table name
        self.audit_reports_table = 'aws_security_audit_reports'
    
    def create_tables(self):
        """Create DynamoDB table if it doesn't exist"""
        try:
            self._create_audit_reports_table()
            logger.info("DynamoDB table created successfully")
            return True
        except Exception as e:
            logger.error(f"Error creating table: {e}")
            return False
    
    def _create_audit_reports_table(self):
        """Create audit reports table"""
        try:
            table = self.dynamodb.create_table(
                TableName=self.audit_reports_table,
                KeySchema=[
                    {'AttributeName': 'report_id', 'KeyType': 'HASH'},
                    {'AttributeName': 'timestamp', 'KeyType': 'RANGE'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'report_id', 'AttributeType': 'S'},
                    {'AttributeName': 'timestamp', 'AttributeType': 'N'},
                    {'AttributeName': 'account_id', 'AttributeType': 'S'},
                    {'AttributeName': 'region', 'AttributeType': 'S'}
                ],
                GlobalSecondaryIndexes=[
                    {
                        'IndexName': 'account-timestamp-index',
                        'KeySchema': [
                            {'AttributeName': 'account_id', 'KeyType': 'HASH'},
                            {'AttributeName': 'timestamp', 'KeyType': 'RANGE'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
                    },
                    {
                        'IndexName': 'region-timestamp-index',
                        'KeySchema': [
                            {'AttributeName': 'region', 'KeyType': 'HASH'},
                            {'AttributeName': 'timestamp', 'KeyType': 'RANGE'}
                        ],
                        'Projection': {'ProjectionType': 'ALL'},
                        'ProvisionedThroughput': {'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
                    }
                ],
                ProvisionedThroughput={'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5}
            )
            table.wait_until_exists()
            logger.info(f"Created table: {self.audit_reports_table}")
        except self.dynamodb.meta.client.exceptions.ResourceInUseException:
            logger.info(f"Table {self.audit_reports_table} already exists")
    

    
    def save_audit_report(self, report_data):
        """Save audit report to DynamoDB"""
        try:
            table = self.dynamodb.Table(self.audit_reports_table)
            
            # Convert floats to Decimal for DynamoDB
            report_data = json.loads(json.dumps(report_data), parse_float=Decimal)
            
            table.put_item(Item=report_data)
            logger.info(f"Saved audit report: {report_data.get('report_id')}")
            return True
        except self.dynamodb.meta.client.exceptions.ResourceNotFoundException:
            # Table doesn't exist, create it
            logger.info(f"Table {self.audit_reports_table} not found, creating...")
            self.create_tables()
            # Retry save
            try:
                table = self.dynamodb.Table(self.audit_reports_table)
                table.put_item(Item=report_data)
                logger.info(f"Saved audit report after creating table: {report_data.get('report_id')}")
                return True
            except Exception as retry_error:
                logger.error(f"Error saving audit report after table creation: {retry_error}")
                return False
        except Exception as e:
            logger.error(f"Error saving audit report: {e}")
            return False
    
    def get_audit_report(self, report_id, timestamp):
        """Get specific audit report"""
        try:
            table = self.dynamodb.Table(self.audit_reports_table)
            response = table.get_item(
                Key={'report_id': report_id, 'timestamp': timestamp}
            )
            return response.get('Item')
        except Exception as e:
            logger.error(f"Error getting audit report: {e}")
            return None
    
    def list_audit_reports(self, limit=50):
        """List recent audit reports"""
        try:
            table = self.dynamodb.Table(self.audit_reports_table)
            response = table.scan(Limit=limit)
            items = response.get('Items', [])
            
            # Sort by timestamp descending
            items.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
            return items
        except Exception as e:
            logger.error(f"Error listing audit reports: {e}")
            return []
    
    def get_reports_by_account(self, account_id, limit=20):
        """Get audit reports for specific account"""
        try:
            table = self.dynamodb.Table(self.audit_reports_table)
            response = table.query(
                IndexName='account-timestamp-index',
                KeyConditionExpression='account_id = :account_id',
                ExpressionAttributeValues={':account_id': account_id},
                Limit=limit,
                ScanIndexForward=False
            )
            return response.get('Items', [])
        except Exception as e:
            logger.error(f"Error getting reports by account: {e}")
            return []
    
    def get_dashboard_stats(self):
        """Get statistics for dashboard"""
        try:
            table = self.dynamodb.Table(self.audit_reports_table)
            response = table.scan()
            items = response.get('Items', [])
            
            total_reports = len(items)
            total_findings = sum(item.get('total_findings', 0) for item in items)
            critical_findings = sum(item.get('critical_findings', 0) for item in items)
            high_findings = sum(item.get('high_findings', 0) for item in items)
            medium_findings = sum(item.get('medium_findings', 0) for item in items)
            low_findings = sum(item.get('low_findings', 0) for item in items)
            
            # Get unique accounts and regions
            accounts = set(item.get('account_id') for item in items if item.get('account_id'))
            regions = set(item.get('region') for item in items if item.get('region'))
            
            # Sort items by timestamp for recent reports
            sorted_items = sorted(items, key=lambda x: x.get('timestamp', 0), reverse=True)
            
            # Get reports over time (last 6 months)
            from collections import defaultdict
            reports_by_month = defaultdict(int)
            for item in items:
                if item.get('scan_date'):
                    try:
                        # Extract month from scan_date
                        month = item['scan_date'][:7]  # YYYY-MM format
                        reports_by_month[month] += 1
                    except:
                        pass
            
            # Get last 6 months
            from datetime import datetime, timedelta
            now = datetime.now()
            months = []
            month_counts = []
            for i in range(5, -1, -1):
                month_date = now - timedelta(days=30*i)
                month_key = month_date.strftime('%Y-%m')
                month_label = month_date.strftime('%b')
                months.append(month_label)
                month_counts.append(reports_by_month.get(month_key, 0))
            
            return {
                'total_reports': total_reports,
                'total_findings': total_findings,
                'critical_findings': critical_findings,
                'high_findings': high_findings,
                'medium_findings': medium_findings,
                'low_findings': low_findings,
                'accounts_scanned': len(accounts),
                'regions_scanned': len(regions),
                'recent_reports': sorted_items[:10],
                'chart_months': months,
                'chart_counts': month_counts
            }
        except Exception as e:
            logger.error(f"Error getting dashboard stats: {e}")
            return {
                'total_reports': 0,
                'total_findings': 0,
                'critical_findings': 0,
                'high_findings': 0,
                'medium_findings': 0,
                'low_findings': 0,
                'accounts_scanned': 0,
                'regions_scanned': 0,
                'recent_reports': [],
                'chart_months': ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                'chart_counts': [0, 0, 0, 0, 0, 0]
            }
    
    def delete_audit_report(self, report_id, timestamp):
        """Delete audit report"""
        try:
            table = self.dynamodb.Table(self.audit_reports_table)
            table.delete_item(
                Key={'report_id': report_id, 'timestamp': timestamp}
            )
            logger.info(f"Deleted audit report: {report_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting audit report: {e}")
            return False
    

