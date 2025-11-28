"""
AWS Service Base Class
Inspired by Prowler's provider pattern
"""

import boto3
from typing import Optional, Dict
import logging

logger = logging.getLogger(__name__)

class AWSService:
    """Base class for AWS service clients"""
    
    def __init__(self, service_name: str, region: str, credentials: Optional[Dict] = None):
        self.service_name = service_name
        self.region = region
        self.credentials = credentials
        self._client = None
        self._resource = None
    
    @property
    def client(self):
        """Lazy-load boto3 client"""
        if self._client is None:
            client_kwargs = {'region_name': self.region}
            if self.credentials:
                client_kwargs.update({
                    'aws_access_key_id': self.credentials['aws_access_key_id'],
                    'aws_secret_access_key': self.credentials['aws_secret_access_key'],
                    'aws_session_token': self.credentials['aws_session_token']
                })
            self._client = boto3.client(self.service_name, **client_kwargs)
        return self._client
    
    @property
    def resource(self):
        """Lazy-load boto3 resource"""
        if self._resource is None:
            resource_kwargs = {'region_name': self.region}
            if self.credentials:
                resource_kwargs.update({
                    'aws_access_key_id': self.credentials['aws_access_key_id'],
                    'aws_secret_access_key': self.credentials['aws_secret_access_key'],
                    'aws_session_token': self.credentials['aws_session_token']
                })
            self._resource = boto3.resource(self.service_name, **resource_kwargs)
        return self._resource
