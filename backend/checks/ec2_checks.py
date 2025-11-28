"""
EC2 Security Checks
Prowler-inspired modular check structure
"""

from typing import List, Dict
from backend.services.aws_service import AWSService
import logging

logger = logging.getLogger(__name__)

class EC2Checks:
    """EC2 security checks"""
    
    def __init__(self, region: str, credentials: Dict = None):
        self.ec2_service = AWSService('ec2', region, credentials)
        self.elb_service = AWSService('elbv2', region, credentials)
        self.region = region
    
    def check_security_groups_open(self) -> List[Dict]:
        """Check for security groups with 0.0.0.0/0 access - excluding ALB/NLB"""
        try:
            logger.info(f"[{self.region}] Checking EC2 security groups...")
            sgs = self.ec2_service.client.describe_security_groups()['SecurityGroups']
            
            # Get load balancer security groups to exclude
            lb_security_groups = set()
            try:
                load_balancers = self.elb_service.client.describe_load_balancers()['LoadBalancers']
                for lb in load_balancers:
                    lb_security_groups.update(lb.get('SecurityGroups', []))
            except Exception as e:
                logger.debug(f"Could not fetch load balancers: {str(e)}")
            
            open_sgs = []
            for sg in sgs:
                sg_id = sg['GroupId']
                
                # Skip ALB/NLB security groups
                if sg_id in lb_security_groups:
                    continue
                
                for perm in sg['IpPermissions']:
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            open_sgs.append({
                                'GroupId': sg_id,
                                'GroupName': sg.get('GroupName', 'N/A'),
                                'Port': f"{perm.get('FromPort', 'All')}-{perm.get('ToPort', 'All')}",
                                'Protocol': perm.get('IpProtocol', 'All'),
                                'VpcId': sg.get('VpcId', 'N/A'),
                                'Description': sg.get('Description', 'No description')[:50]
                            })
                            break
            
            logger.info(f"[{self.region}] Found {len(open_sgs)} open security groups")
            return open_sgs
        except Exception as e:
            logger.error(f"[{self.region}] Error checking security groups: {str(e)}")
            return []
    
    def check_imdsv2_enforcement(self) -> List[Dict]:
        """Check for EC2 instances not using IMDSv2"""
        try:
            logger.info(f"[{self.region}] Checking EC2 IMDSv2 enforcement...")
            instances = self.ec2_service.client.describe_instances()
            
            non_compliant = []
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    metadata_options = instance.get('MetadataOptions', {})
                    http_tokens = metadata_options.get('HttpTokens', 'optional')
                    
                    if http_tokens != 'required':
                        non_compliant.append({
                            'InstanceId': instance['InstanceId'],
                            'InstanceType': instance.get('InstanceType', 'unknown'),
                            'State': instance['State']['Name'],
                            'IMDSv2': 'Not Enforced'
                        })
            
            logger.info(f"[{self.region}] Found {len(non_compliant)} instances without IMDSv2")
            return non_compliant
        except Exception as e:
            logger.error(f"[{self.region}] Error checking IMDSv2: {str(e)}")
            return []
    
    def check_unused_key_pairs(self) -> List[Dict]:
        """Check for unused EC2 key pairs"""
        try:
            logger.info(f"[{self.region}] Checking unused key pairs...")
            key_pairs = self.ec2_service.client.describe_key_pairs()['KeyPairs']
            instances = self.ec2_service.client.describe_instances()
            
            # Get all key pairs in use
            used_keys = set()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if instance.get('KeyName'):
                        used_keys.add(instance['KeyName'])
            
            unused = []
            for kp in key_pairs:
                if kp['KeyName'] not in used_keys:
                    unused.append({
                        'KeyName': kp['KeyName'],
                        'KeyPairId': kp.get('KeyPairId', 'N/A'),
                        'Status': 'Unused'
                    })
            
            logger.info(f"[{self.region}] Found {len(unused)} unused key pairs")
            return unused
        except Exception as e:
            logger.error(f"[{self.region}] Error checking key pairs: {str(e)}")
            return []
