import React, { useState } from 'react';
import { Eye, ExternalLink, Copy, Check } from 'lucide-react';
import './LogsViewer.css';

const LogsViewer = () => {
  const [copied, setCopied] = useState(false);

  const awsConsoleUrl = "https://console.aws.amazon.com/cloudwatch/home#logsV2:log-groups/log-group/$252Faws$252Fcloudmitigator$252Faudit";
  
  const cliCommands = [
    {
      title: "List CloudMitigator log groups",
      command: 'aws logs describe-log-groups --log-group-name-prefix "/aws/cloudmitigator"'
    },
    {
      title: "View recent audit logs (last hour)",
      command: 'aws logs filter-log-events --log-group-name "/aws/cloudmitigator/audit" --start-time $(date -d "1 hour ago" +%s)000'
    },
    {
      title: "View logs for specific TTP (e.g., T1078)",
      command: 'aws logs filter-log-events --log-group-name "/aws/cloudmitigator/audit" --filter-pattern "T1078"'
    },
    {
      title: "View only mitigation actions",
      command: 'aws logs filter-log-events --log-group-name "/aws/cloudmitigator/audit" --filter-pattern "mitigation_action"'
    }
  ];

  const copyToClipboard = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy text: ', err);
    }
  };

  return (
    <div className="logs-viewer">
      <div className="logs-viewer-header">
        <Eye size={20} />
        <h3>CloudWatch Audit Logs</h3>
      </div>

      <div className="logs-info">
        <p>All mitigation actions are automatically logged to CloudWatch for audit trail purposes.</p>
        <p><strong>Log Group:</strong> <code>/aws/cloudmitigator/audit</code></p>
      </div>

      <div className="logs-access-methods">
        <div className="access-method">
          <h4>AWS Console</h4>
          <p>View logs directly in the AWS CloudWatch console:</p>
          <a 
            href={awsConsoleUrl}
            target="_blank" 
            rel="noopener noreferrer"
            className="console-link"
          >
            <ExternalLink size={16} />
            Open CloudWatch Logs
          </a>
        </div>

        <div className="access-method">
          <h4>AWS CLI Commands</h4>
          <p>Use these commands to view logs from your terminal:</p>
          
          {cliCommands.map((cmd, index) => (
            <div key={index} className="cli-command">
              <div className="command-header">
                <span className="command-title">{cmd.title}</span>
                <button 
                  className="copy-button"
                  onClick={() => copyToClipboard(cmd.command)}
                  title="Copy command"
                >
                  {copied ? <Check size={14} /> : <Copy size={14} />}
                </button>
              </div>
              <code className="command-text">{cmd.command}</code>
            </div>
          ))}
        </div>
      </div>

      <div className="log-format">
        <h4>Log Entry Format</h4>
        <p>Each log entry contains structured JSON data:</p>
        <pre className="log-example">
{`{
  "timestamp": "2025-10-03T19:00:00Z",
  "event_type": "mitigation_action",
  "ttp_id": "T1078",
  "action": "mitigate_mfa_enforce",
  "success": true,
  "execution_time_ms": 1250,
  "details": {
    "users_enforced": ["test"]
  },
  "source": "cloudmitigator"
}`}
        </pre>
      </div>
    </div>
  );
};

export default LogsViewer;
