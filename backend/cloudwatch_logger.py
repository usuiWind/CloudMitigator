import boto3
import json
import logging
from datetime import datetime
from typing import Dict, Optional
from botocore.exceptions import ClientError, BotoCoreError

class CloudWatchAuditLogger:
    """CloudWatch audit logger for TTP mitigation actions"""
    
    def __init__(self, session: Optional[boto3.Session] = None, log_group_name: str = '/aws/cloudmitigator/audit'):
        self.session = session or boto3.Session()
        self.log_group_name = log_group_name
        self.log_stream_name = f"mitigation-actions-{datetime.now().strftime('%Y-%m-%d')}"
        self.cloudwatch_logs = None
        self.logger = logging.getLogger(__name__)
        
        # Initialize CloudWatch Logs client
        self._initialize_cloudwatch()
    
    def _initialize_cloudwatch(self):
        """Initialize CloudWatch Logs client and ensure log group/stream exist"""
        try:
            self.cloudwatch_logs = self.session.client('logs')
            self.logger.info(f"Initializing CloudWatch logging to: {self.log_group_name}")
            self._ensure_log_group_exists()
            self._ensure_log_stream_exists()
            self.logger.info("CloudWatch audit logging initialized successfully")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            
            if error_code == 'AccessDeniedException' and 'explicit deny' in error_msg:
                self.logger.warning("⚠️  CloudWatch logging disabled due to IAM policy restrictions")
                self.logger.warning("Application will continue with local logging only")
                self.logger.info("To enable CloudWatch logging:")
                self.logger.info("1. Remove explicit deny policies for logs:* actions")
                self.logger.info("2. Or manually create log group: aws logs create-log-group --log-group-name '/aws/cloudmitigator/audit'")
            else:
                self.logger.error(f"AWS CloudWatch Error [{error_code}]: {error_msg}")
                self.logger.error("CLI Command to check permissions: aws logs describe-log-groups --limit 1")
                self.logger.error("Required permissions: logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents")
            
            self.cloudwatch_logs = None
        except Exception as e:
            self.logger.error(f"Failed to initialize CloudWatch logging: {e}")
            self.logger.error("Verify AWS credentials are configured: aws sts get-caller-identity")
            self.cloudwatch_logs = None
    
    def _ensure_log_group_exists(self):
        """Create log group if it doesn't exist"""
        try:
            self.cloudwatch_logs.create_log_group(logGroupName=self.log_group_name)
            self.logger.info(f"✓ Created CloudWatch log group: {self.log_group_name}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
                self.logger.info(f"✓ CloudWatch log group already exists: {self.log_group_name}")
            else:
                error_code = e.response['Error']['Code']
                error_msg = e.response['Error']['Message']
                self.logger.error(f"✗ Failed to create log group [{error_code}]: {error_msg}")
                self.logger.error(f"CLI Command: aws logs create-log-group --log-group-name '{self.log_group_name}'")
                raise
    
    def _ensure_log_stream_exists(self):
        """Create log stream if it doesn't exist"""
        try:
            self.cloudwatch_logs.create_log_stream(
                logGroupName=self.log_group_name,
                logStreamName=self.log_stream_name
            )
            self.logger.info(f"✓ Created CloudWatch log stream: {self.log_stream_name}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
                self.logger.info(f"✓ CloudWatch log stream already exists: {self.log_stream_name}")
            else:
                error_code = e.response['Error']['Code']
                error_msg = e.response['Error']['Message']
                self.logger.error(f"✗ Failed to create log stream [{error_code}]: {error_msg}")
                self.logger.error(f"CLI Command: aws logs create-log-stream --log-group-name '{self.log_group_name}' --log-stream-name '{self.log_stream_name}'")
                raise
    
    def log_mitigation_action(self, 
                            ttp_id: str, 
                            action: str, 
                            success: bool, 
                            details: Dict = None,
                            user_info: Dict = None,
                            execution_time_ms: Optional[int] = None) -> bool:
        """
        Log a mitigation action to CloudWatch
        
        Args:
            ttp_id: The TTP identifier (e.g., T1078)
            action: The action taken (e.g., "enforce_mfa", "create_waf_acl")
            success: Whether the action succeeded
            details: Additional details about the action
            user_info: Information about the user who triggered the action
            execution_time_ms: How long the action took in milliseconds
        
        Returns:
            bool: True if logged successfully, False otherwise
        """
        if not self.cloudwatch_logs:
            self.logger.warning("CloudWatch logging not available - audit trail will be local only")
            return False
        
        try:
            # Create structured log entry
            log_entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": "mitigation_action",
                "ttp_id": ttp_id,
                "action": action,
                "success": success,
                "execution_time_ms": execution_time_ms,
                "details": details or {},
                "user_info": user_info or {},
                "source": "cloudmitigator"
            }
            
            # Send to CloudWatch
            response = self.cloudwatch_logs.put_log_events(
                logGroupName=self.log_group_name,
                logStreamName=self.log_stream_name,
                logEvents=[
                    {
                        'timestamp': int(datetime.utcnow().timestamp() * 1000),
                        'message': json.dumps(log_entry, default=str)
                    }
                ]
            )
            
            self.logger.info(f"✓ Logged mitigation action to CloudWatch: {ttp_id} - {action}")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            self.logger.error(f"✗ CloudWatch logging failed [{error_code}]: {error_msg}")
            self.logger.error(f"CLI Debug: aws logs describe-log-streams --log-group-name '{self.log_group_name}'")
            return False
        except Exception as e:
            self.logger.error(f"✗ Failed to log to CloudWatch: {e}")
            self.logger.error("Check AWS credentials and permissions")
            return False
    
    def log_status_check(self, 
                        ttp_id: str, 
                        instances_found: int, 
                        check_details: Dict = None) -> bool:
        """
        Log a status check to CloudWatch
        
        Args:
            ttp_id: The TTP identifier
            instances_found: Number of instances needing mitigation
            check_details: Details about what was checked
        
        Returns:
            bool: True if logged successfully, False otherwise
        """
        if not self.cloudwatch_logs:
            return False
        
        try:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": "status_check",
                "ttp_id": ttp_id,
                "instances_found": instances_found,
                "check_details": check_details or {},
                "source": "cloudmitigator"
            }
            
            response = self.cloudwatch_logs.put_log_events(
                logGroupName=self.log_group_name,
                logStreamName=self.log_stream_name,
                logEvents=[
                    {
                        'timestamp': int(datetime.utcnow().timestamp() * 1000),
                        'message': json.dumps(log_entry, default=str)
                    }
                ]
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to log status check to CloudWatch: {e}")
            return False
    
    def log_demo_action(self, ttp_id: str, demo_message: str) -> bool:
        """
        Log a demo mode action to CloudWatch
        
        Args:
            ttp_id: The TTP identifier
            demo_message: The demo message shown to user
        
        Returns:
            bool: True if logged successfully, False otherwise
        """
        if not self.cloudwatch_logs:
            return False
        
        try:
            log_entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": "demo_action",
                "ttp_id": ttp_id,
                "demo_message": demo_message,
                "source": "cloudmitigator"
            }
            
            response = self.cloudwatch_logs.put_log_events(
                logGroupName=self.log_group_name,
                logStreamName=self.log_stream_name,
                logEvents=[
                    {
                        'timestamp': int(datetime.utcnow().timestamp() * 1000),
                        'message': json.dumps(log_entry, default=str)
                    }
                ]
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to log demo action to CloudWatch: {e}")
            return False
    
    def test_cloudwatch_connectivity(self) -> Dict:
        """Test CloudWatch connectivity and return diagnostic information"""
        result = {
            'cloudwatch_available': False,
            'log_group_exists': False,
            'log_stream_exists': False,
            'can_write_logs': False,
            'errors': [],
            'cli_commands': []
        }
        
        if not self.cloudwatch_logs:
            result['errors'].append("CloudWatch client not initialized")
            result['cli_commands'].append("aws sts get-caller-identity")
            return result
        
        result['cloudwatch_available'] = True
        
        # Test log group
        try:
            response = self.cloudwatch_logs.describe_log_groups(logGroupNamePrefix=self.log_group_name)
            log_groups = response.get('logGroups', [])
            log_group_found = any(lg['logGroupName'] == self.log_group_name for lg in log_groups)
            
            if log_group_found:
                result['log_group_exists'] = True
                self.logger.info(f"✓ Log group exists: {self.log_group_name}")
            else:
                result['errors'].append(f"Log group does not exist: {self.log_group_name}")
                result['cli_commands'].append(f"aws logs create-log-group --log-group-name '{self.log_group_name}'")
        except ClientError as e:
            result['errors'].append(f"Log group check failed: {e.response['Error']['Message']}")
            result['cli_commands'].append(f"aws logs create-log-group --log-group-name '{self.log_group_name}'")
        
        # Test log stream
        try:
            self.cloudwatch_logs.describe_log_streams(
                logGroupName=self.log_group_name,
                logStreamNamePrefix=self.log_stream_name
            )
            result['log_stream_exists'] = True
            self.logger.info(f"✓ Log stream exists: {self.log_stream_name}")
        except ClientError as e:
            result['errors'].append(f"Log stream check failed: {e.response['Error']['Message']}")
            result['cli_commands'].append(f"aws logs create-log-stream --log-group-name '{self.log_group_name}' --log-stream-name '{self.log_stream_name}'")
        
        # Test write capability
        try:
            test_entry = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": "connectivity_test",
                "message": "CloudWatch connectivity test",
                "source": "cloudmitigator"
            }
            
            self.cloudwatch_logs.put_log_events(
                logGroupName=self.log_group_name,
                logStreamName=self.log_stream_name,
                logEvents=[
                    {
                        'timestamp': int(datetime.utcnow().timestamp() * 1000),
                        'message': json.dumps(test_entry)
                    }
                ]
            )
            result['can_write_logs'] = True
            self.logger.info("✓ CloudWatch write test successful")
        except ClientError as e:
            result['errors'].append(f"Write test failed: {e.response['Error']['Message']}")
            result['cli_commands'].append(f"aws logs filter-log-events --log-group-name '{self.log_group_name}' --limit 1")
        
        return result
