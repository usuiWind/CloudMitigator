# AWS Permissions for CloudMitigator

## Complete IAM Policy (Copy & Paste)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers", "iam:ListMFADevices", "iam:CreatePolicy", "iam:AttachUserPolicy",
        "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret", "secretsmanager:UpdateSecret", "secretsmanager:TagResource",
        "wafv2:ListWebACLs", "wafv2:CreateWebACL", "wafv2:UpdateWebACL",
        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:CreateTrail", "cloudtrail:StartLogging",
        "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Read-Only (Testing)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers", "iam:ListMFADevices",
        "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
        "wafv2:ListWebACLs", "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Setup Instructions

1. **AWS Console**: IAM → Policies → Create Policy → JSON → Paste above
2. **AWS CLI**: 
   ```bash
   aws iam create-policy --policy-name CloudMitigatorPolicy --policy-document file://policy.json
   aws iam attach-user-policy --user-name YOUR_USER --policy-arn POLICY_ARN
   ```

## Feature Permissions

- **T1078 (MFA)**: `iam:ListUsers`, `iam:ListMFADevices`, `iam:CreatePolicy`
- **T1552 (Secrets)**: `secretsmanager:ListSecrets`, `secretsmanager:DescribeSecret`
- **T1110 (WAF)**: `wafv2:ListWebACLs`, `wafv2:CreateWebACL`
- **T1098 (CloudTrail)**: `cloudtrail:DescribeTrails`, `cloudtrail:CreateTrail`
- **CloudWatch Logs**: `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`

## Troubleshooting

- **AccessDenied**: Check explicit deny policies on your user
- **CloudWatch fails**: Run `aws logs create-log-group --log-group-name '/aws/cloudmitigator/audit'`
- **No instances detected**: Verify you have AWS resources that need mitigation
