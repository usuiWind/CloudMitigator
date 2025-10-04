from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import logging
from config import Config
from ttp_mapper import TTPMapper
from mitigations import MitigationService

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

# Initialize services
ttp_mapper = TTPMapper(app.config['TTP_MAPPINGS_PATH'])
mitigation_service = MitigationService(
    region=app.config['AWS_REGION'],
    access_key=app.config['AWS_ACCESS_KEY_ID'],
    secret_key=app.config['AWS_SECRET_ACCESS_KEY']
)


@app.route('/status', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'CloudMitigator API',
        'version': '1.0.0'
    }), 200


@app.route('/ttps', methods=['GET'])
def get_ttps():
    """Get all TTPs from mappings"""
    try:
        search_query = request.args.get('search', '').lower()
        ttps = ttp_mapper.get_all_ttps()
        
        # Debug logging
        logger.info(f"Loaded TTPs: {list(ttps.keys())}")
        
        if search_query:
            filtered_ttps = {
                ttp_id: ttp_data
                for ttp_id, ttp_data in ttps.items()
                if search_query in ttp_id.lower() or 
                   search_query in ttp_data.get('name', '').lower() or
                   search_query in ttp_data.get('description', '').lower()
            }
            return jsonify(filtered_ttps), 200
        
        return jsonify(ttps), 200
    except Exception as e:
        logger.error(f"Error fetching TTPs: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/ttps/<ttp_id>', methods=['GET'])
def get_ttp(ttp_id):
    """Get specific TTP by ID"""
    try:
        ttp = ttp_mapper.get_ttp(ttp_id.upper())
        if ttp:
            return jsonify(ttp), 200
        return jsonify({'error': 'TTP not found'}), 404
    except Exception as e:
        logger.error(f"Error fetching TTP {ttp_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/ttps/<ttp_id>/status', methods=['GET'])
def get_ttp_status(ttp_id):
    """Get the current status of a TTP (how many instances need mitigation)"""
    try:
        ttp_id = ttp_id.upper()
        ttp = ttp_mapper.get_ttp(ttp_id)
        
        if not ttp:
            return jsonify({'error': 'TTP not found'}), 404
        
        # Check if credentials are valid first
        creds_status = mitigation_service.validate_credentials()
        
        if not creds_status['valid']:
            # Demo mode - return simulated status with different counts per TTP
            demo_instances = {
                'T1078': 3,  # 3 users without MFA
                'T1552': 2,  # 2 secrets without rotation
                'T1110': 1,  # 1 WAF ACL needed
                'T1098': 1   # 1 CloudTrail needed
            }
            
            instance_count = demo_instances.get(ttp_id, 1)
            return jsonify({
                'ttp_id': ttp_id,
                'instances_needing_mitigation': instance_count,
                'demo_mode': True,
                'message': f"Demo: {instance_count} instance{'s' if instance_count > 1 else ''} need{'s' if instance_count == 1 else ''} {ttp['mitigation'].lower()}"
            }), 200
        
        # Get the mitigation function
        function_name = ttp.get('function')
        if not hasattr(mitigation_service, function_name):
            return jsonify({'error': f'Mitigation function {function_name} not found'}), 500
        
        # Call the mitigation function to check current status (without applying mitigation)
        mitigation_func = getattr(mitigation_service, function_name)
        result = mitigation_func(apply_mitigation=False)
        
        # Debug logging
        logger.info(f"Status check for {ttp_id}: {result}")
        
        # Check if the result indicates an error
        if not result.get('success', True):
            message = result.get('message', '')
            # Check for AWS permission errors
            if 'not authorized' in message or 'AccessDenied' in message:
                # AWS permission error - assume mitigation is needed
                instances_count = 1
                logger.warning(f"AWS permission error for {ttp_id}, assuming mitigation needed: {message}")
                return jsonify({
                    'ttp_id': ttp_id,
                    'instances_needing_mitigation': instances_count,
                    'demo_mode': False,
                    'message': f'Permission check failed - assuming mitigation needed'
                }), 200
            else:
                # Other error - return error response
                logger.error(f"Status check failed for {ttp_id}: {message}")
                return jsonify({
                    'ttp_id': ttp_id,
                    'instances_needing_mitigation': 0,
                    'demo_mode': False,
                    'error': message
                }), 500
        
        # Extract the number of instances needing mitigation based on the TTP type
        instances_count = 0
        message = result.get('message', '')
        
        if 'details' in result and result['details']:
            details = result['details']
            logger.info(f"Details for {ttp_id}: {details}")
            
            # T1078 - MFA enforcement
            if 'users_without_mfa' in details:
                instances_count = len(details['users_without_mfa'])
            # T1552 - Secrets rotation
            elif 'secrets_without_rotation' in details:
                instances_count = len(details['secrets_without_rotation'])
            elif 'secrets_configured' in details:
                # After mitigation, check if there are still secrets needing rotation
                instances_count = details.get('total_secrets', 0) - details.get('secrets_configured', 0)
            # T1110 - WAF rate limiting
            elif 'rate_limiting_enabled' in details:
                instances_count = 0  # WAF is already configured
            elif 'needs_waf_acl' in details:
                instances_count = 1  # Need to create WAF ACL
            # T1098 - CloudTrail
            elif 'cloudtrail_enabled' in details:
                instances_count = 0  # CloudTrail is already logging
            elif 'trails_not_logging' in details:
                instances_count = len(details['trails_not_logging'])  # Number of trails not logging
            elif 'trails_enabled' in details and 'total_trails' in details:
                # After mitigation - check if all trails were enabled
                remaining = details.get('total_trails', 0) - details.get('trails_enabled', 0)
                instances_count = max(0, remaining)  # Should be 0 if all were enabled
            elif 'needs_logging' in details or 'needs_cloudtrail' in details:
                instances_count = 1  # CloudTrail needs to be enabled/created
            elif 'trails_logging' in details:
                instances_count = 0  # All trails are logging
        
        # Log status check to CloudWatch
        if hasattr(mitigation_service, 'audit_logger') and mitigation_service.audit_logger:
            mitigation_service.audit_logger.log_status_check(
                ttp_id=ttp_id,
                instances_found=instances_count,
                check_details={
                    'message': result.get('message', ''),
                    'success': result.get('success', True),
                    'details': result.get('details', {})
                }
            )
        
        return jsonify({
            'ttp_id': ttp_id,
            'instances_needing_mitigation': instances_count,
            'demo_mode': False,
            'message': result.get('message', '')
        }), 200
        
    except Exception as e:
        logger.error(f"Error checking TTP status {ttp_id}: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/mitigate/<ttp_id>', methods=['POST'])
def mitigate_ttp(ttp_id):
    """Apply mitigation for a specific TTP"""
    try:
        ttp_id = ttp_id.upper()
        ttp = ttp_mapper.get_ttp(ttp_id)
        
        if not ttp:
            return jsonify({'error': 'TTP not found'}), 404
        
        # Get optional parameters from request body
        params = request.get_json() or {}
        
        # Check if credentials are valid first
        creds_status = mitigation_service.validate_credentials()
        
        if not creds_status['valid']:
            # Demo mode - return simulated success response
            demo_messages = {
                'T1078': 'Demo: Would enforce MFA on 3 IAM users without MFA enabled',
                'T1552': 'Demo: Would enable rotation for 2 secrets in Secrets Manager',
                'T1110': 'Demo: Would create WAF rate limiting rules for brute force protection',
                'T1098': 'Demo: Would enable CloudTrail logging for IAM account changes'
            }
            
            demo_message = demo_messages.get(ttp_id, f'Demo: Would apply {ttp["mitigation"]}')
            
            # Log demo action to CloudWatch
            if hasattr(mitigation_service, 'audit_logger') and mitigation_service.audit_logger:
                mitigation_service.audit_logger.log_demo_action(ttp_id, demo_message)
            
            logger.info(f"Demo mode mitigation for {ttp_id}")
            return jsonify({
                'success': True,
                'ttp_id': ttp_id,
                'message': demo_message,
                'details': {'demo_mode': True, 'reason': 'AWS credentials not configured'}
            }), 200
        
        # Execute actual mitigation
        result = mitigation_service.execute_mitigation(
            ttp_id=ttp_id,
            function_name=ttp['function'],
            params=params
        )
        
        if result['success']:
            logger.info(f"Successfully mitigated {ttp_id}")
            return jsonify({
                'success': True,
                'ttp_id': ttp_id,
                'message': result['message'],
                'details': result.get('details', {})
            }), 200
        else:
            logger.error(f"Failed to mitigate {ttp_id}: {result['message']}")
            return jsonify({
                'success': False,
                'ttp_id': ttp_id,
                'error': result['message']
            }), 500
            
    except Exception as e:
        logger.error(f"Error mitigating TTP {ttp_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/logs', methods=['GET'])
def get_logs():
    """Get recent mitigation logs"""
    try:
        logs = mitigation_service.get_recent_logs(limit=50)
        return jsonify(logs), 200
    except Exception as e:
        logger.error(f"Error fetching logs: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/credentials/status', methods=['GET'])
def check_credentials_status():
    """Check AWS credentials status"""
    status = mitigation_service.validate_credentials()
    return jsonify({
        'valid': status['valid'],
        'message': status.get('message', ''),
        'details': status.get('details', {})
    }), 200


@app.route('/cloudwatch/test', methods=['GET'])
def test_cloudwatch():
    """Test CloudWatch logging connectivity and permissions"""
    try:
        if hasattr(mitigation_service, 'audit_logger') and mitigation_service.audit_logger:
            result = mitigation_service.audit_logger.test_cloudwatch_connectivity()
            return jsonify(result), 200
        else:
            return jsonify({
                'cloudwatch_available': False,
                'errors': ['CloudWatch audit logger not initialized'],
                'cli_commands': ['Check backend logs for initialization errors']
            }), 200
    except Exception as e:
        logger.error(f"CloudWatch test error: {str(e)}")
        return jsonify({
            'cloudwatch_available': False,
            'errors': [str(e)],
            'cli_commands': ['aws sts get-caller-identity', 'aws logs describe-log-groups --limit 1']
        }), 500


@app.route('/debug/status/<ttp_id>', methods=['GET'])
def debug_ttp_status(ttp_id):
    """Debug endpoint to see detailed TTP status information"""
    try:
        if ttp_id not in ttps:
            return jsonify({'error': f'TTP {ttp_id} not found'}), 404
        
        ttp = ttps[ttp_id]
        function_name = ttp.get('function')
        
        if not hasattr(mitigation_service, function_name):
            return jsonify({'error': f'Mitigation function {function_name} not found'}), 500
        
        # Call the mitigation function to check current status
        mitigation_func = getattr(mitigation_service, function_name)
        result = mitigation_func(apply_mitigation=False)
        
        # Return full debug information
        return jsonify({
            'ttp_id': ttp_id,
            'ttp_info': ttp,
            'function_name': function_name,
            'raw_result': result,
            'credentials_valid': mitigation_service.validate_credentials()
        }), 200
        
    except Exception as e:
        logger.error(f"Debug error for {ttp_id}: {str(e)}")
        return jsonify({'error': str(e), 'traceback': str(e.__traceback__)})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=app.config['FLASK_DEBUG'])
