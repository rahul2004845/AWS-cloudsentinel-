# CloudSentinel CSPM + Exposure Management

CloudSentinel now includes a **read-only CSPM scanner**. It collects AWS API
evidence and creates posture findings that can be investigated beside UEBA,
CloudTrail, GuardDuty, and Security Hub data. No scan changes any AWS resource.

## Checks included

- Root-user MFA and IAM user MFA coverage
- S3 public-access-block configuration and default encryption
- Internet-exposed SSH/RDP or all-traffic EC2 security-group rules
- EBS encryption by default
- CloudTrail presence and active logging
- CloudTrail S3 object data-event coverage (needed for GetObject/PutObject detection)
- AWS Config recording coverage (needed for configuration-change evidence)
- GuardDuty and Security Hub activation

Each finding includes severity, resource, evidence, remediation guidance and
control mappings. Failed/unauthorized AWS API calls are returned as **scan
errors**, never treated as passing checks.

## Enable it safely

1. Copy `backend/.env.example` to `backend/.env` and set:

   ```env
   CSPM_ENABLED=true
   CSPM_REGIONS=ap-south-1,us-east-1
   ENABLE_DEV_ENDPOINTS=true
   DEV_ADMIN_API_KEY=<long-random-admin-key>
   ```

2. Attach a dedicated, least-privilege role to the backend workload. The role
   should be read-only and allow only the APIs below:

   ```text
   sts:GetCallerIdentity
   s3:ListAllMyBuckets, s3:GetBucketPublicAccessBlock, s3:GetEncryptionConfiguration
   iam:GetAccountSummary, iam:ListUsers, iam:ListMFADevices
   ec2:DescribeSecurityGroups, ec2:GetEbsEncryptionByDefault
   cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus, cloudtrail:GetEventSelectors
   config:DescribeConfigurationRecorders, config:DescribeConfigurationRecorderStatus
   guardduty:ListDetectors, guardduty:GetDetector
   securityhub:DescribeHub
   ```

3. Run a scan from an administrative terminal. The scan endpoint is protected
   because it can enumerate your AWS estate:

   ```powershell
   Invoke-RestMethod -Method Post http://localhost:8000/api/cspm/scan `
     -Headers @{ 'X-Admin-Key' = '<long-random-admin-key>' }
   ```

4. Read results at `GET /api/cspm/findings`, or use the **Exposure Management**
   dashboard tab. For production, schedule this protected operation through an
   EventBridge-triggered worker every 6–24 hours instead of exposing credentials
   to a browser.

## How it connects to investigations

Use a posture finding as attack context: an anomalous IAM login linked to a
public S3 bucket or public administrative security group is materially more
urgent than either isolated signal. The next production increment should link
findings to incidents by resource ARN/account and require an analyst approval
before any remediation workflow is run.
