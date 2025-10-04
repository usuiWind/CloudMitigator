# CloudMitigator Setup Guide

## Step-by-Step Setup Instructions

### 1. AWS Credentials Setup

#### Option A: Using AWS CLI (Recommended)
```bash
aws configure
```
Enter your:
- AWS Access Key ID
- AWS Secret Access Key
- Default region (e.g., us-east-1)
- Default output format (json)

#### Option B: Manual Configuration
Create `backend/.env` file:
```env
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
FLASK_ENV=development
FLASK_DEBUG=True
```

### 2. Docker Setup (Easiest)

```bash
# Start all services
docker-compose up --build

# Run in background
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### 3. Manual Setup (Development)

#### Backend Setup
```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run Flask app
python app.py
```

Backend will run on: http://localhost:5000

#### Frontend Setup
```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm start
```

Frontend will run on: http://localhost:3000

### 4. Verify Installation

#### Check Backend
```bash
curl http://localhost:5000/status
```

Expected response:
```json
{
  "status": "healthy",
  "service": "CloudMitigator API",
  "version": "1.0.0"
}
```

#### Check Frontend
Open browser: http://localhost:3000

You should see:
- CloudMitigator header
- Search bar
- Sidebar with AWS service filters
- TTP cards

### 5. Test AWS Connectivity

```bash
# Test IAM mitigation (read-only check)
curl -X POST http://localhost:5000/mitigate/T1078
```

### 6. Running Tests

#### Backend Tests
```bash
cd backend
pytest ../tests/ -v
```

#### Frontend Tests
```bash
cd frontend
npm test
```

### 7. Production Build

#### Backend
```bash
cd backend
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

#### Frontend
```bash
cd frontend
npm run build
# Serve the build folder with a static server
```

## Troubleshooting

### Issue: "Module not found" errors
**Solution**: Ensure you're in the correct directory and virtual environment is activated

### Issue: AWS credentials not working
**Solution**: 
1. Verify credentials with `aws sts get-caller-identity`
2. Check IAM permissions
3. Ensure `.env` file is in `backend/` directory

### Issue: Port already in use
**Solution**: 
```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# macOS/Linux
lsof -ti:5000 | xargs kill -9
```

### Issue: CORS errors in browser
**Solution**: Ensure backend is running and CORS is enabled in `app.py`

### Issue: Docker containers won't start
**Solution**:
```bash
docker-compose down
docker system prune -a
docker-compose up --build
```

## Next Steps

1. ✅ Verify all services are running
2. ✅ Test TTP search functionality
3. ✅ Test mitigation actions (start with read-only checks)
4. ✅ Review AWS CloudTrail logs for API calls
5. ✅ Add custom TTPs to `data/ttp_mappings.json`
6. ✅ Implement additional mitigation functions

## Security Best Practices

1. **Never commit `.env` files** to version control
2. **Use IAM roles** instead of access keys when possible
3. **Enable MFA** on AWS accounts
4. **Use least privilege** IAM policies
5. **Rotate credentials** regularly
6. **Monitor CloudTrail logs** for API activity
7. **Use AWS Secrets Manager** for production credentials

## Support

For issues or questions:
1. Check the main README.md
2. Review error logs: `docker-compose logs`
3. Open an issue on GitHub
