import React, { useState } from 'react';
import { ChevronDown, ChevronUp, ExternalLink, Copy } from 'lucide-react';
import './SetupGuide.css';

const SetupGuide = () => {
  const [isExpanded, setIsExpanded] = useState(false);

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="setup-guide">
      <button 
        className="setup-guide-toggle"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <span>AWS Credentials Setup Guide</span>
        {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
      </button>
      
      {isExpanded && (
        <div className="setup-guide-content">
          <h3>Configure AWS Credentials</h3>
          <p>To use the mitigation features, you need to configure AWS credentials. Here are the options:</p>
          
          <div className="setup-method">
            <h4>Option 1: Environment Variables (Recommended for Docker)</h4>
            <p>Set these environment variables in your <code>docker-compose.yml</code> or <code>.env</code> file:</p>
            <div className="code-block">
              <code>
                AWS_ACCESS_KEY_ID=your_access_key_here<br/>
                AWS_SECRET_ACCESS_KEY=your_secret_key_here<br/>
                AWS_REGION=us-east-1
              </code>
              <button 
                className="copy-button"
                onClick={() => copyToClipboard('AWS_ACCESS_KEY_ID=your_access_key_here\nAWS_SECRET_ACCESS_KEY=your_secret_key_here\nAWS_REGION=us-east-1')}
              >
                <Copy size={14} />
              </button>
            </div>
          </div>

          <div className="setup-method">
            <h4>Option 2: AWS CLI Configuration</h4>
            <p>Install AWS CLI and run:</p>
            <div className="code-block">
              <code>aws configure</code>
              <button 
                className="copy-button"
                onClick={() => copyToClipboard('aws configure')}
              >
                <Copy size={14} />
              </button>
            </div>
          </div>

          <div className="setup-method">
            <h4>Option 3: IAM Roles (For EC2/ECS)</h4>
            <p>If running on AWS infrastructure, attach an IAM role with appropriate permissions.</p>
          </div>

          <div className="permissions-info">
            <h4>Required AWS Permissions</h4>
            <p>Your credentials need the following permissions:</p>
            <ul>
              <li><code>iam:ListUsers</code>, <code>iam:ListMFADevices</code>, <code>iam:CreatePolicy</code>, <code>iam:AttachUserPolicy</code></li>
              <li><code>secretsmanager:ListSecrets</code>, <code>secretsmanager:DescribeSecret</code>, <code>secretsmanager:UpdateSecret</code></li>
              <li><code>wafv2:ListWebACLs</code>, <code>wafv2:CreateWebACL</code></li>
              <li><code>cloudtrail:DescribeTrails</code>, <code>cloudtrail:StartLogging</code>, <code>cloudtrail:CreateTrail</code></li>
              <li><code>logs:CreateLogGroup</code>, <code>logs:CreateLogStream</code>, <code>logs:PutLogEvents</code></li>
              <li><code>sts:GetCallerIdentity</code></li>
            </ul>
            <p><strong>CloudWatch Logs:</strong> All mitigation actions are automatically logged to CloudWatch for audit trail purposes.</p>
          </div>

          <div className="external-links">
            <a 
              href="https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html" 
              target="_blank" 
              rel="noopener noreferrer"
              className="external-link"
            >
              AWS Configuration Guide <ExternalLink size={14} />
            </a>
          </div>
        </div>
      )}
    </div>
  );
};

export default SetupGuide;
