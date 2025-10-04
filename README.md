# CloudMitigator 🛡️

**Automated AWS Security Mitigations for MITRE ATT&CK TTPs**

CloudMitigator is a comprehensive security automation platform that detects AWS security gaps and applies MITRE ATT&CK-based mitigations in real-time. It features intelligent status monitoring, comprehensive audit logging, and automated remediation for critical AWS security controls.

![Tech Stack](https://img.shields.io/badge/React-18.2-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![Python](https://img.shields.io/badge/Python-3.11-yellow)
![AWS](https://img.shields.io/badge/AWS-boto3-orange)
![CloudWatch](https://img.shields.io/badge/CloudWatch-Logging-purple)

---

## Key Features

### **Intelligent Security Monitoring**
- **Real-time Status Detection**: Automatically detects AWS resources needing security mitigations
- **Dynamic Button Colors**: Visual indicators (Red = Action Needed, Green = Secure)
- **Instance Counting**: Shows exact number of resources requiring attention

### **Automated Mitigations**
- **One-Click Remediation**: Apply security fixes directly from the UI
- **Smart Configuration**: Handles existing AWS resources intelligently
- **Batch Operations**: Processes multiple resources simultaneously

### **Comprehensive Audit Trail**
- **CloudWatch Integration**: All actions logged to AWS CloudWatch
- **Structured Logging**: JSON-formatted logs with timing and details
- **Demo Mode Support**: Full functionality without AWS credentials for testing

### **Advanced TTP Coverage**
- **4 Critical TTPs**: MFA enforcement, secrets rotation, WAF protection, CloudTrail logging
- **AWS Service Integration**: Direct integration with IAM, Secrets Manager, WAF, CloudTrail
- **Permission Management**: Granular IAM permission requirements

---

## Project Structure

```
AWS-Automatic-TTP-Mitigation-/
├── frontend/                 # React.js frontend
│   ├── src/
│   │   ├── components/       # UI components (Header, Sidebar, SearchBar, TTPCard, etc.)
│   │   ├── services/         # API service layer
│   │   ├── App.js            # Main application component
│   │   └── index.js          # Entry point
│   ├── public/
│   ├── package.json
│   └── Dockerfile
│
├── backend/                  # Flask API backend
│   ├── app.py                # Main Flask application with status endpoints
│   ├── ttp_mapper.py         # TTP mapping logic
│   ├── mitigations.py        # AWS mitigation functions (boto3)
│   ├── cloudwatch_logger.py  # CloudWatch audit logging service
│   ├── config.py             # Configuration management
│   ├── requirements.txt
│   └── Dockerfile
│
├── data/
│   └── ttp_mappings.json     # TTP → AWS service mappings
│
├── tests/                    # Unit tests
│   ├── test_api.py           # Flask API tests
│   └── test_ttp_mapper.py    # TTP mapper tests
│
├── docker-compose.yml        # Docker orchestration
├── AWS_PERMISSIONS.md        # Complete AWS IAM permissions guide
└── README.md                 # This file
```

---

## Tech Stack

### Frontend
- **React.js 18.2** - Modern UI framework
- **Lucide React** - Beautiful icon library
- **React Toastify** - Toast notifications
- **Axios** - HTTP client

### Backend
- **Flask 3.0** - Lightweight Python web framework
- **boto3** - AWS SDK for Python
- **Flask-CORS** - Cross-origin resource sharing
- **CloudWatch Logs** - Centralized audit logging

### Infrastructure
- **Docker & Docker Compose** - Containerization
- **AWS CloudWatch** - Monitoring and logging
- **pytest** - Python testing framework

---

## Prerequisites

- **Docker** and **Docker Compose** installed
- **AWS Account** with appropriate IAM permissions
- **AWS Credentials** (Access Key ID & Secret Access Key)

---

## Quick Start

### 1. Clone the Repository

```bash
cd AWS-Automatic-TTP-Mitigation-
```

### 2. Configure AWS Permissions

**Apply the required IAM policy** from `AWS_PERMISSIONS.md`:

```bash
# Copy the complete policy from AWS_PERMISSIONS.md
aws iam create-policy --policy-name CloudMitigatorPolicy --policy-document file://policy.json
aws iam attach-user-policy --user-name YOUR_USER --policy-arn POLICY_ARN
```

### 3. Configure AWS Credentials

**Option A: Environment Variables (Recommended for Docker)**
```bash
# Set environment variables
export AWS_ACCESS_KEY_ID=your_access_key_here
export AWS_SECRET_ACCESS_KEY=your_secret_key_here
export AWS_DEFAULT_REGION=us-east-2
```

**Option B: AWS CLI Configuration**
```bash
aws configure
```

**Option C: Create .env file**
```env
AWS_REGION=us-east-2
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
FLASK_ENV=development
FLASK_DEBUG=True
```

 **Security Note**: Never commit `.env` files to version control!

### 4. Start the Application with Docker

```bash
docker compose build
docker compose up
```

This will:
- Build and start the Flask backend on `http://localhost:5000`
- Build and start the React frontend on `http://localhost:3000`
- Initialize CloudWatch audit logging (if permissions allow)

### 5. Access the Application

Open your browser and navigate to:
```
http://localhost:3000
```

### 6. Verify Setup

- **Credentials Status**: Check the header for AWS connection status
- **TTP Cards**: Should show red/green buttons based on your AWS resources
- **Demo Mode**: Available if AWS credentials are not configured

---

## 🔧 Manual Setup (Without Docker)

### Backend Setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # macOS/Linux
pip install -r requirements.txt
python app.py
```

### Frontend Setup

```bash
cd frontend
npm install
npm start
```

---

## Running Tests

### Backend Tests (pytest)

```bash
cd backend
pytest ../tests/
```

### Frontend Tests (Jest)

```bash
cd frontend
npm test
```

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/status` | Health check |
| `GET` | `/ttps` | Get all TTPs (supports `?search=query`) |
| `GET` | `/ttps/<ttp_id>` | Get specific TTP by ID |
| `GET` | `/ttps/<ttp_id>/status` | Check TTP mitigation status |
| `POST` | `/mitigate/<ttp_id>` | Apply mitigation for TTP |
| `GET` | `/credentials/status` | Check AWS credentials validity |
| `GET` | `/cloudwatch/test` | Test CloudWatch logging connectivity |
| `GET` | `/debug/status/<ttp_id>` | Detailed TTP status debugging |
| `GET` | `/logs` | Get recent mitigation logs |

### Example API Calls

```bash
# Check TTP status (red/green button logic)
curl http://localhost:5000/ttps/T1078/status

# Check credentials
curl http://localhost:5000/credentials/status

# Test CloudWatch logging
curl http://localhost:5000/cloudwatch/test

# Debug TTP status
curl http://localhost:5000/debug/status/T1552

# Apply mitigation
curl -X POST http://localhost:5000/mitigate/T1078
```

---

## UI Components

### Header
- CloudMitigator branding with shield icon
- **AWS Connection Status**: Real-time credential validation
- **Demo Mode Indicator**: Shows when running without AWS credentials

### Sidebar
- **AWS Service Filter**: All, IAM, Secrets Manager, WAF, CloudTrail
- **TTP Count Display**: Dynamic count based on filters
- **Credentials Setup Guide**: Expandable help section

### TTP Cards
- **TTP ID Badge**: MITRE ATT&CK identifier with alert icon
- **AWS Service Badge**: Service-specific color coding
- **Status Indicator**: Instance count needing mitigation
- **Dynamic Buttons**: 
  - 🔴 **Red**: Action needed (shows count)
  - 🟢 **Green**: Secure (no action needed)
- **Real-time Updates**: Status refreshes after mitigation

---

## AWS Permissions Required

** See `AWS_PERMISSIONS.md` for complete IAM policy details.**

### Quick Setup
```bash
# Copy the complete policy from AWS_PERMISSIONS.md
aws iam create-policy --policy-name CloudMitigatorPolicy --policy-document file://policy.json
aws iam attach-user-policy --user-name YOUR_USER --policy-arn POLICY_ARN
```

### Required Permissions Summary
- **IAM**: `ListUsers`, `ListMFADevices`, `CreatePolicy`, `AttachUserPolicy`
- **Secrets Manager**: `ListSecrets`, `DescribeSecret`, `UpdateSecret`, `TagResource`
- **WAF**: `ListWebACLs`, `CreateWebACL`, `UpdateWebACL`
- **CloudTrail**: `DescribeTrails`, `GetTrailStatus`, `StartLogging`
- **CloudWatch Logs**: `CreateLogGroup`, `CreateLogStream`, `PutLogEvents`
- **STS**: `GetCallerIdentity`

### Permission Modes
- **Complete Policy**: Full mitigation capabilities
- **Read-Only Policy**: Status checking only (for testing)

---

## Supported TTPs

| TTP ID | Name | AWS Service | Mitigation | Status Detection |
|--------|------|-------------|------------|------------------|
| **T1078** | Valid Accounts | IAM | Enforce MFA on users | Counts users without MFA |
| **T1552** | Unsecured Credentials | Secrets Manager | Enable rotation + tagging | Detects secrets without rotation |
| **T1110** | Brute Force | WAF | Create rate limiting rules | Checks for WAF Web ACLs |
| **T1098** | Account Manipulation | CloudTrail | Start logging on trails | Counts trails not logging |

### TTP Features
- ** Smart Detection**: Automatically scans your AWS environment
- ** Instance Counting**: Shows exact number of resources needing attention
- ** Batch Processing**: Handles multiple resources simultaneously
- ** Configuration Tracking**: Uses tags to track CloudMitigator actions
- ** CloudWatch Logging**: All actions logged with timing and details

---

## Adding New TTPs

1. Edit `data/ttp_mappings.json`:

```json
{
  "T1234": {
    "name": "New TTP Name",
    "description": "Description of the TTP",
    "mitigation": "What mitigation does",
    "aws_service": "service_name",
    "function": "mitigate_function_name"
  }
}
```

2. Add mitigation function in `backend/mitigations.py`:

```python
def mitigate_function_name(self, **params) -> Dict:
    """Mitigation description"""
    try:
        # Your boto3 code here
        client = self.session.client('service_name')
        # ... implementation
        return {'success': True, 'message': 'Success message'}
    except ClientError as e:
        return {'success': False, 'message': f"Error: {e}"}
```

---

## Troubleshooting

### Red Buttons Not Turning Green
- **Check AWS permissions**: Ensure you have all required IAM permissions
- **Debug endpoint**: Use `/debug/status/<ttp_id>` to see detailed status
- **CloudWatch logs**: Check backend logs for permission errors

### AWS Permission Errors
- **"AccessDeniedException"**: Missing required IAM permissions
- **"explicit deny"**: Your user has a restrictive policy attached
- **Solution**: Apply the complete policy from `AWS_PERMISSIONS.md`

### Connection Issues
- **Backend won't start**: Check AWS credentials and Python dependencies
- **Frontend won't connect**: Verify backend is running on port 5000
- **Docker issues**: Try `docker compose down && docker compose build --no-cache`

### CloudWatch Logging Issues
- **Test endpoint**: Use `/cloudwatch/test` to diagnose issues
- **Missing log group**: Run `aws logs create-log-group --log-group-name '/aws/cloudmitigator/audit'`
- **Permission errors**: Ensure `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`

### Demo Mode
- **No AWS credentials**: Application automatically switches to demo mode
- **Full functionality**: All features work with simulated responses
- **Testing**: Perfect for UI/UX testing without AWS resources

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-ttp`
3. Commit your changes: `git commit -am 'Add new TTP mitigation'`
4. Push to the branch: `git push origin feature/new-ttp`
5. Submit a pull request

---

## License

This project is licensed under the MIT License.

---

## Acknowledgments

- **MITRE ATT&CK** for the TTP framework
- **AWS** for the boto3 SDK
- **React** and **Flask** communities

---


