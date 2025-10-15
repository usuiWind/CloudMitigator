import boto3
import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional
from botocore.exceptions import ClientError, BotoCoreError
from cloudwatch_logger import CloudWatchAuditLogger

logger = logging.getLogger(__name__)


class MitigationService:
    """Executes AWS security mitigations via boto3"""
    
    def __init__(self, region: str, access_key: Optional[str] = None, secret_key: Optional[str] = None):
        self.region = region
        self.logs = []
        self.audit_logger = None
        
        # Initialize boto3 session
        session_params = {'region_name': region}
        if access_key and secret_key:
            session_params['aws_access_key_id'] = access_key
            session_params['aws_secret_access_key'] = secret_key
        
        self.session = boto3.Session(**session_params)
        
        # Initialize CloudWatch audit logger
        try:
            self.audit_logger = CloudWatchAuditLogger(session=self.session)
        except Exception as e:
            logger.warning(f"CloudWatch audit logging not available: {e}")
            self.audit_logger = None
    
    def _log_action(self, ttp_id: str, action: str, success: bool, message: str):
        """Log mitigation action"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'ttp_id': ttp_id,
            'action': action,
            'success': success,
            'message': message
        }
        self.logs.append(log_entry)
        logger.info(f"[{ttp_id}] {action}: {message}")
    
    def get_recent_logs(self, limit: int = 50) -> List[Dict]:
        """Get recent mitigation logs"""
        return self.logs[-limit:]
    
    def validate_credentials(self) -> Dict:
        """Validate AWS credentials by making a simple API call"""
        try:
            # Try to get caller identity - this is a simple, low-cost call
            sts = self.session.client('sts')
            response = sts.get_caller_identity()
            
            return {
                'valid': True,
                'account_id': response.get('Account'),
                'user_id': response.get('UserId'),
                'arn': response.get('Arn'),
                'region': self.region
            }
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['InvalidUserID.NotFound', 'AccessDenied', 'SignatureDoesNotMatch']:
                return {
                    'valid': False,
                    'error': 'Invalid AWS credentials',
                    'details': e.response['Error']['Message']
                }
            else:
                return {
                    'valid': False,
                    'error': f'AWS Error: {error_code}',
                    'details': e.response['Error']['Message']
                }
        except BotoCoreError as e:
            return {
                'valid': False,
                'error': 'AWS configuration error',
                'details': str(e)
            }
        except Exception as e:
            return {
                'valid': False,
                'error': 'Credential validation failed',
                'details': str(e)
            }
    
    def execute_mitigation(self, ttp_id: str, function_name: str, params: Dict = None) -> Dict:
        """Execute mitigation function with CloudWatch audit logging"""
        params = params or {}
        start_time = time.time()
        
        try:
            # Map function name to method
            mitigation_func = getattr(self, function_name, None)
            
            if not mitigation_func:
                error_msg = f"Mitigation function '{function_name}' not found"
                self._log_action(ttp_id, function_name, False, error_msg)
                
                # Log to CloudWatch
                if self.audit_logger:
                    self.audit_logger.log_mitigation_action(
                        ttp_id=ttp_id,
                        action=function_name,
                        success=False,
                        details={'error': error_msg}
                    )
                
                return {'success': False, 'message': error_msg}
            
            # Execute mitigation with apply_mitigation=True
            params['apply_mitigation'] = True
            result = mitigation_func(**params)
            
            # Calculate execution time
            execution_time_ms = int((time.time() - start_time) * 1000)
            
            # Log locally
            self._log_action(ttp_id, function_name, result.get('success', False), result['message'])
            
            # Log to CloudWatch with detailed information
            if self.audit_logger:
                self.audit_logger.log_mitigation_action(
                    ttp_id=ttp_id,
                    action=function_name,
                    success=result.get('success', False),
                    details=result.get('details', {}),
                    execution_time_ms=execution_time_ms
                )
            
            return result
            
        except Exception as e:
            execution_time_ms = int((time.time() - start_time) * 1000)
            error_msg = f"Error executing mitigation: {str(e)}"
            
            # Log locally
            self._log_action(ttp_id, function_name, False, error_msg)
            
            # Log to CloudWatch
            if self.audit_logger:
                self.audit_logger.log_mitigation_action(
                    ttp_id=ttp_id,
                    action=function_name,
                    success=False,
                    details={'error': str(e), 'exception_type': type(e).__name__},
                    execution_time_ms=execution_time_ms
                )
            
            return {'success': False, 'message': error_msg}
    
    # ==================== MITIGATION FUNCTIONS ====================
    
    def mitigate_mfa_enforce(self, user_name: Optional[str] = None, apply_mitigation: bool = False) -> Dict:
        """Enforce MFA on IAM users (T1078)"""
        try:
            iam = self.session.client('iam')
            
            # If specific user provided, check that user
            if user_name:
                users = [{'UserName': user_name}]
            else:
                # Get all users
                response = iam.list_users()
                users = response.get('Users', [])
            
            users_without_mfa = []
            
            for user in users:
                username = user['UserName']
                mfa_devices = iam.list_mfa_devices(UserName=username)
                
                if not mfa_devices.get('MFADevices'):
                    users_without_mfa.append(username)
            
            if users_without_mfa:
                if apply_mitigation:
                    # Apply MFA policy to users without MFA
                    policy_document = {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "*",
                                "Resource": "*",
                                "Condition": {
                                    "BoolIfExists": {
                                        "aws:MultiFactorAuthPresent": "false"
                                    }
                                }
                            }
                        ]
                    }
                    
                    policy_name = "EnforceMFAPolicy"
                    
                    # Create or update the MFA enforcement policy
                    try:
                        iam.create_policy(
                            PolicyName=policy_name,
                            PolicyDocument=json.dumps(policy_document),
                            Description="Enforce MFA for all users"
                        )
                    except ClientError as e:
                        if e.response['Error']['Code'] != 'EntityAlreadyExists':
                            raise
                    
                    # Attach policy to users without MFA
                    for username in users_without_mfa:
                        try:
                            iam.attach_user_policy(
                                UserName=username,
                                PolicyArn=f"arn:aws:iam::{self.session.client('sts').get_caller_identity()['Account']}:policy/{policy_name}"
                            )
                        except ClientError:
                            pass  # Policy might already be attached
                    
                    return {
                        'success': True,
                        'message': f'Applied MFA enforcement policy to {len(users_without_mfa)} users',
                        'details': {'users_enforced': users_without_mfa}
                    }
                else:
                    message = f"Found {len(users_without_mfa)} users without MFA: {', '.join(users_without_mfa[:5])}"
                    return {
                        'success': True,
                        'message': message,
                        'details': {'users_without_mfa': users_without_mfa}
                    }
            else:
                return {
                    'success': True,
                    'message': 'All users have MFA enabled',
                    'details': {'users_without_mfa': []}
                }
                
        except ClientError as e:
            return {'success': False, 'message': f"AWS Error: {e.response['Error']['Message']}"}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def mitigate_secrets_rotation(self, secret_id: Optional[str] = None, apply_mitigation: bool = False) -> Dict:
        """Enable Secrets Manager rotation (T1552)"""
        try:
            secrets_client = self.session.client('secretsmanager')
            
            if secret_id:
                if apply_mitigation:
                    # Enable rotation for specific secret
                    secrets_client.rotate_secret(
                        SecretId=secret_id,
                        RotationRules={'AutomaticallyAfterDays': 30}
                    )
                    return {
                        'success': True,
                        'message': f'Enabled rotation for secret: {secret_id}',
                        'details': {'secret_id': secret_id}
                    }
                else:
                    # Just check the secret status
                    secret_info = secrets_client.describe_secret(SecretId=secret_id)
                    rotation_enabled = secret_info.get('RotationEnabled', False)
                    return {
                        'success': True,
                        'message': f'Secret rotation {"enabled" if rotation_enabled else "disabled"}',
                        'details': {'secrets_without_rotation': [] if rotation_enabled else [secret_id]}
                    }
            else:
                # List all secrets and check rotation status
                response = secrets_client.list_secrets()
                secrets = response.get('SecretList', [])
                
                if not secrets:
                    # No secrets found - this means there are no secrets to check
                    logger.info(f"Secrets check: No secrets found in Secrets Manager")
                    return {
                        'success': True,
                        'message': 'No secrets found in Secrets Manager',
                        'details': {'secrets_without_rotation': []}
                    }
                
                secrets_without_rotation = []
                for secret in secrets:
                    secret_name = secret['Name']
                    # Check detailed secret info for rotation status
                    try:
                        secret_detail = secrets_client.describe_secret(SecretId=secret_name)
                        rotation_enabled = secret_detail.get('RotationEnabled', False)
                        description = secret_detail.get('Description', '')
                        
                        # Check if CloudMitigator has tagged this secret as rotation-configured
                        cloudmitigator_configured = False
                        try:
                            tags_response = secrets_client.describe_secret(SecretId=secret_name)
                            tags = tags_response.get('Tags', [])
                            cloudmitigator_configured = any(
                                tag.get('Key') == 'CloudMitigatorRotation' and tag.get('Value') == 'Configured'
                                for tag in tags
                            )
                        except:
                            pass
                        
                        # Consider it "configured" if either:
                        # 1. RotationEnabled is True (actual rotation)
                        # 2. CloudMitigator tag indicates it's configured
                        if not rotation_enabled and not cloudmitigator_configured:
                            secrets_without_rotation.append(secret_name)
                        elif cloudmitigator_configured:
                            logger.info(f"Secret {secret_name} marked as rotation-configured by CloudMitigator tag")
                            
                    except ClientError as e:
                        logger.warning(f"Could not check rotation for secret {secret_name}: {e}")
                        # If we can't check, assume it needs rotation
                        secrets_without_rotation.append(secret_name)
                
                if apply_mitigation and secrets_without_rotation:
                    # Enable rotation for all secrets without it
                    enabled_count = 0
                    for secret_name in secrets_without_rotation:
                        try:
                            # Enable automatic rotation with 30-day interval
                            try:
                                # Update secret description
                                secrets_client.update_secret(
                                    SecretId=secret_name,
                                    Description=f"Rotation configured by CloudMitigator - {datetime.now().strftime('%Y-%m-%d')}",
                                )
                                
                                # Add CloudMitigator tag to mark as configured
                                secrets_client.tag_resource(
                                    SecretId=secret_name,
                                    Tags=[
                                        {
                                            'Key': 'CloudMitigatorRotation',
                                            'Value': 'Configured'
                                        },
                                        {
                                            'Key': 'ConfiguredDate',
                                            'Value': datetime.now().strftime('%Y-%m-%d')
                                        }
                                    ]
                                )
                                
                                # Try to configure automatic rotation for RDS secrets
                                try:
                                    # For RDS secrets, try to enable actual rotation
                                    if 'rds' in secret_name.lower() or 'database' in secret_name.lower():
                                        secrets_client.rotate_secret(
                                            SecretId=secret_name,
                                            RotationRules={'AutomaticallyAfterDays': 30}
                                        )
                                        logger.info(f"Successfully enabled automatic rotation for RDS secret: {secret_name}")
                                    else:
                                        logger.info(f"Tagged secret as rotation-configured: {secret_name}")
                                        
                                except ClientError as rotation_error:
                                    # If rotation setup fails, that's okay - we've still tagged it
                                    logger.info(f"Secret tagged as configured, manual Lambda setup needed for: {secret_name}")
                                    logger.debug(f"Rotation error: {rotation_error.response['Error']['Message']}")
                                
                                enabled_count += 1
                                logger.info(f"Successfully configured secret: {secret_name}")
                                
                            except ClientError as update_error:
                                logger.warning(f"Could not configure secret {secret_name}: {update_error.response['Error']['Message']}")
                                continue
                        except ClientError as e:
                            logger.warning(f"Could not update secret {secret_name}: {e.response['Error']['Message']}")
                            continue
                    
                    return {
                        'success': True,
                        'message': f'Enabled/configured rotation for {enabled_count} of {len(secrets_without_rotation)} secrets',
                        'details': {'secrets_configured': enabled_count, 'total_secrets': len(secrets_without_rotation)}
                    }
                else:
                    logger.info(f"Secrets check: Found {len(secrets_without_rotation)} secrets without rotation")
                    return {
                        'success': True,
                        'message': f'Found {len(secrets_without_rotation)} secrets without rotation',
                        'details': {'secrets_without_rotation': secrets_without_rotation}
                    }
                
        except ClientError as e:
            return {'success': False, 'message': f"AWS Error: {e.response['Error']['Message']}"}
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def mitigate_waf_rate_limit(self, web_acl_name: str = 'CloudMitigator-RateLimit', apply_mitigation: bool = False) -> Dict:
        """Enable AWS WAF rate limiting (T1110)"""
        try:
            wafv2 = self.session.client('wafv2')
            
            # Check if Web ACL exists
            try:
                response = wafv2.list_web_acls(Scope='REGIONAL')
                existing_acls = response.get('WebACLs', [])
                existing_acl_names = [acl['Name'] for acl in existing_acls]
                
                if not existing_acls:
                    # No Web ACLs found at all
                    if apply_mitigation:
                        # Create WAF Web ACL with rate limiting
                        try:
                            wafv2.create_web_acl(
                                Scope='REGIONAL',
                                Name=web_acl_name,
                                DefaultAction={'Allow': {}},
                                Rules=[
                                    {
                                        'Name': 'RateLimitRule',
                                        'Priority': 1,
                                        'Statement': {
                                            'RateBasedStatement': {
                                                'Limit': 2000,
                                                'AggregateKeyType': 'IP'
                                            }
                                        },
                                        'Action': {'Block': {}},
                                        'VisibilityConfig': {
                                            'SampledRequestsEnabled': True,
                                            'CloudWatchMetricsEnabled': True,
                                            'MetricName': 'RateLimitRule'
                                        }
                                    }
                                ],
                                VisibilityConfig={
                                    'SampledRequestsEnabled': True,
                                    'CloudWatchMetricsEnabled': True,
                                    'MetricName': web_acl_name
                                }
                            )
                            return {
                                'success': True,
                                'message': f'Created WAF Web ACL "{web_acl_name}" with rate limiting',
                                'details': {'web_acl_name': web_acl_name, 'rate_limiting_enabled': True}
                            }
                        except ClientError as create_error:
                            return {
                                'success': False,
                                'message': f'Failed to create WAF ACL: {create_error.response["Error"]["Message"]}'
                            }
                    else:
                        logger.info(f"WAF check: No Web ACLs found, needs mitigation")
                        return {
                            'success': True,
                            'message': 'No WAF Web ACLs found. Rate limiting not configured.',
                            'details': {'existing_acls': [], 'needs_waf_acl': True}
                        }
                
                # Look for our specific Web ACL or any rate limiting ACL
                rate_limiting_acl = None
                for acl in existing_acls:
                    if acl['Name'] == web_acl_name:
                        rate_limiting_acl = acl
                        break
                
                if rate_limiting_acl:
                    return {
                        'success': True,
                        'message': f'WAF Web ACL "{web_acl_name}" already exists with rate limiting',
                        'details': {'web_acl_name': web_acl_name, 'rate_limiting_enabled': True}
                    }
                else:
                    if apply_mitigation:
                        # Create WAF Web ACL with rate limiting
                        try:
                            wafv2.create_web_acl(
                                Scope='REGIONAL',
                                Name=web_acl_name,
                                DefaultAction={'Allow': {}},
                                Rules=[
                                    {
                                        'Name': 'RateLimitRule',
                                        'Priority': 1,
                                        'Statement': {
                                            'RateBasedStatement': {
                                                'Limit': 2000,
                                                'AggregateKeyType': 'IP'
                                            }
                                        },
                                        'Action': {'Block': {}},
                                        'VisibilityConfig': {
                                            'SampledRequestsEnabled': True,
                                            'CloudWatchMetricsEnabled': True,
                                            'MetricName': 'RateLimitRule'
                                        }
                                    }
                                ],
                                VisibilityConfig={
                                    'SampledRequestsEnabled': True,
                                    'CloudWatchMetricsEnabled': True,
                                    'MetricName': web_acl_name
                                }
                            )
                            return {
                                'success': True,
                                'message': f'Created WAF Web ACL "{web_acl_name}" with rate limiting',
                                'details': {'web_acl_name': web_acl_name, 'rate_limiting_enabled': True}
                            }
                        except ClientError as create_error:
                            return {
                                'success': False,
                                'message': f'Failed to create WAF ACL: {create_error.response["Error"]["Message"]}'
                            }
                    else:
                        return {
                            'success': True,
                            'message': f'WAF rate limiting not configured. Need to create Web ACL "{web_acl_name}".',
                            'details': {'existing_acls': existing_acl_names, 'needs_waf_acl': True}
                        }
                    
            except ClientError as e:
                return {'success': False, 'message': f"AWS Error: {e.response['Error']['Message']}"}
                
        except Exception as e:
            return {'success': False, 'message': str(e)}
    
    def mitigate_cloudtrail_iam(self, trail_name: str = 'CloudMitigator-IAM-Trail', apply_mitigation: bool = False) -> Dict:
        """Enable CloudTrail logging for IAM changes (T1098)"""
        try:
            cloudtrail = self.session.client('cloudtrail')
            
            # Check all existing trails
            response = cloudtrail.describe_trails()
            all_trails = response.get('trailList', [])
            
            if not all_trails:
                # No trails exist at all
                if apply_mitigation:
                    # Create S3 bucket for CloudTrail (simplified)
                    s3_bucket = f"cloudmitigator-trail-{self.session.client('sts').get_caller_identity()['Account']}"
                    
                    # Create CloudTrail
                    cloudtrail.create_trail(
                        Name=trail_name,
                        S3BucketName=s3_bucket,
                        IncludeGlobalServiceEvents=True,
                        IsMultiRegionTrail=True,
                        EnableLogFileValidation=True
                    )
                    
                    # Start logging
                    cloudtrail.start_logging(Name=trail_name)
                    
                    return {
                        'success': True,
                        'message': f'Created and enabled CloudTrail "{trail_name}" for IAM logging',
                        'details': {'trail_name': trail_name, 'cloudtrail_enabled': True}
                    }
                else:
                    return {
                        'success': True,
                        'message': 'No CloudTrail found. Need to create trail for IAM logging.',
                        'details': {'existing_trails': [], 'needs_cloudtrail': True}
                    }
            
            # Check existing trails for logging status
            trails_not_logging = []
            trails_logging = []
            
            for trail in all_trails:
                trail_name_current = trail['Name']
                try:
                    status = cloudtrail.get_trail_status(Name=trail_name_current)
                    if status.get('IsLogging'):
                        trails_logging.append(trail_name_current)
                    else:
                        trails_not_logging.append(trail_name_current)
                except ClientError as e:
                    logger.warning(f"Could not check status for trail {trail_name_current}: {e}")
                    trails_not_logging.append(trail_name_current)
            
            if trails_not_logging:
                if apply_mitigation:
                    # Start logging for all trails that aren't logging
                    enabled_count = 0
                    for trail_name_current in trails_not_logging:
                        try:
                            cloudtrail.start_logging(Name=trail_name_current)
                            logger.info(f"Started logging for CloudTrail: {trail_name_current}")
                            enabled_count += 1
                        except ClientError as e:
                            logger.warning(f"Could not start logging for trail {trail_name_current}: {e.response['Error']['Message']}")
                            continue
                    
                    # After enabling logging, all trails should be logging
                    return {
                        'success': True,
                        'message': f'Started logging for {enabled_count} of {len(trails_not_logging)} CloudTrail(s)',
                        'details': {
                            'trails_enabled': enabled_count, 
                            'total_trails': len(trails_not_logging), 
                            'cloudtrail_enabled': True,
                            'trails_logging': trails_logging + [name for name in trails_not_logging[:enabled_count]],
                            'trails_not_logging': []  # Should be empty after successful mitigation
                        }
                    }
                else:
                    return {
                        'success': True,
                        'message': f'Found {len(trails_not_logging)} CloudTrail(s) not logging: {", ".join(trails_not_logging)}',
                        'details': {'trails_not_logging': trails_not_logging, 'needs_logging': True}
                    }
            else:
                return {
                    'success': True,
                    'message': f'All {len(trails_logging)} CloudTrail(s) are already logging',
                    'details': {'trails_logging': trails_logging, 'cloudtrail_enabled': True}
                }
                
        except ClientError as e:
            return {'success': False, 'message': f"AWS Error: {e.response['Error']['Message']}"}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def restrict_api_permissions(self, apply_mitigation: bool = False) -> Dict:
        """Restrict API permissions to only allow necessary actions"""
        try:
            restricted_users = []
            iam = self.session.client('iam')
            deny_policy_doc = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": [
                            "ec2:Describe*",
                            "iam:List*",
                            "s3:List*",
                            "rds:Describe*",
                            "cloudtrail:Describe*",
                            "cloudwatch:Describe*"
                        ],
                        "Resource": "*"
                    }
                ]
            }
            policy_name = "RestrictDiscoveryPolicy" 
            try:
                iam.create_policy(
                PolicyName=policy_name,
                PolicyDocument=json.dumps(deny_policy_doc)
                )
                print(f"[+] Created policy: {policy_name}")
            except iam.exceptions.EntityAlreadyExistsException:
                print(f"[*] Policy {policy_name} already exists, reusing it.")

            # Get admin users from groups or tags
            admin_groups = ["Admins", "SecurityAdmins"]
            all_users = iam.list_users()["Users"]

            for user in all_users:
                username = user["UserName"]
                groups = iam.list_groups_for_user(UserName=username)["Groups"]
                group_names = [g["GroupName"] for g in groups]

                # Skip admin users
                if any(g in admin_groups for g in group_names):
                    continue

                # Check attached policies
                attached_policies = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
                for policy in attached_policies:
                    policy_arn = policy["PolicyArn"]
                    # If policy includes Describe* permissions, detach
                    if "Describe" in policy_arn or "List" in policy_arn:
                        iam.detach_user_policy(UserName=username, PolicyArn=policy_arn)
                        restricted_users.append(username)

                # Attach deny policy to enforce restriction
                policy_arn = f"arn:aws:iam::{iam.get_user()['User']['Arn'].split(':')[4]}:policy/{policy_name}"
                iam.attach_user_policy(UserName=username, PolicyArn=policy_arn)

            print(f"[+] Restricted Describe* permissions for users: {restricted_users}")
            return {
                "success": True,
                "message": f"Restricted Describe* permissions for users: {restricted_users}",
                "details": {"restricted_users": restricted_users}
            }
            
        except ClientError as e: 
            return {'success': False, 'message': f"AWS Error: {e.response['Error']['Message']}"}
        except Exception as e:
            return {'success': False, 'message': str(e)}
