#!/usr/bin/env python3
"""
CloudWatch Setup Script for CloudMitigator
Creates the required log group and stream for audit logging
"""

import boto3
import sys
from botocore.exceptions import ClientError

def setup_cloudwatch_logging():
    """Setup CloudWatch log group and stream"""
    log_group_name = '/aws/cloudmitigator/audit'
    
    try:
        # Initialize CloudWatch Logs client
        logs_client = boto3.client('logs')
        
        print(f"Setting up CloudWatch logging...")
        print(f"Log Group: {log_group_name}")
        
        # Test AWS credentials first
        try:
            sts = boto3.client('sts')
            identity = sts.get_caller_identity()
            print(f"✓ AWS credentials valid - Account: {identity['Account']}")
        except Exception as e:
            print(f"✗ AWS credentials error: {e}")
            print("Run: aws configure")
            return False
        
        # Create log group
        try:
            logs_client.create_log_group(logGroupName=log_group_name)
            print(f"✓ Created log group: {log_group_name}")
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceAlreadyExistsException':
                print(f"✓ Log group already exists: {log_group_name}")
            else:
                print(f"✗ Failed to create log group: {e.response['Error']['Message']}")
                print(f"Required permission: logs:CreateLogGroup")
                return False
        
        # Verify log group exists
        try:
            response = logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
            log_groups = response.get('logGroups', [])
            log_group_found = any(lg['logGroupName'] == log_group_name for lg in log_groups)
            
            if log_group_found:
                print(f"✓ Verified log group exists: {log_group_name}")
            else:
                print(f"✗ Log group not found after creation: {log_group_name}")
                return False
        except ClientError as e:
            print(f"✗ Failed to verify log group: {e.response['Error']['Message']}")
            return False
        
        print("\n🎉 CloudWatch logging setup complete!")
        print(f"View logs at: https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups/log-group/{log_group_name.replace('/', '$252F')}")
        
        return True
        
    except Exception as e:
        print(f"✗ Setup failed: {e}")
        return False

def test_permissions():
    """Test required CloudWatch permissions"""
    print("\nTesting CloudWatch permissions...")
    
    required_permissions = [
        ('logs:CreateLogGroup', 'create_log_group'),
        ('logs:CreateLogStream', 'create_log_stream'), 
        ('logs:PutLogEvents', 'put_log_events'),
        ('logs:DescribeLogGroups', 'describe_log_groups'),
        ('logs:DescribeLogStreams', 'describe_log_streams')
    ]
    
    logs_client = boto3.client('logs')
    
    for perm_name, _ in required_permissions:
        print(f"  {perm_name}: Required for audit logging")
    
    # Test describe permissions
    try:
        logs_client.describe_log_groups(limit=1)
        print("✓ logs:DescribeLogGroups - OK")
    except ClientError as e:
        print(f"✗ logs:DescribeLogGroups - {e.response['Error']['Message']}")

if __name__ == '__main__':
    print("CloudMitigator CloudWatch Setup")
    print("=" * 40)
    
    if len(sys.argv) > 1 and sys.argv[1] == '--test-permissions':
        test_permissions()
    else:
        success = setup_cloudwatch_logging()
        if not success:
            print("\nTroubleshooting:")
            print("1. Check AWS credentials: aws sts get-caller-identity")
            print("2. Test permissions: python setup_cloudwatch.py --test-permissions")
            print("3. Manual creation: aws logs create-log-group --log-group-name '/aws/cloudmitigator/audit'")
            sys.exit(1)
