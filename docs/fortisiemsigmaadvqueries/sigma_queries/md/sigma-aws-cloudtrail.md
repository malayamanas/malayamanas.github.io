# Sigma → FortiSIEM: Aws Cloudtrail

> 55 rules · Generated 2026-03-17

## Table of Contents

- [AWS Bucket Deleted](#aws-bucket-deleted)
- [AWS ConsoleLogin Failed Authentication](#aws-consolelogin-failed-authentication)
- [AWS Successful Console Login Without MFA](#aws-successful-console-login-without-mfa)
- [AWS CloudTrail Important Change](#aws-cloudtrail-important-change)
- [AWS GuardDuty Detector Deleted Or Updated](#aws-guardduty-detector-deleted-or-updated)
- [Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure](#malicious-usage-of-imds-credentials-outside-of-aws-infrastructure)
- [New Network ACL Entry Added](#new-network-acl-entry-added)
- [New Network Route Added](#new-network-route-added)
- [PUA - AWS TruffleHog Execution](#pua-aws-trufflehog-execution)
- [AWS EnableRegion Command Monitoring](#aws-enableregion-command-monitoring)
- [Ingress/Egress Security Group Modification](#ingressegress-security-group-modification)
- [LoadBalancer Security Group Modification](#loadbalancer-security-group-modification)
- [RDS Database Security Group Modification](#rds-database-security-group-modification)
- [Potential Malicious Usage of CloudTrail System Manager](#potential-malicious-usage-of-cloudtrail-system-manager)
- [AWS VPC Flow Logs Deleted](#aws-vpc-flow-logs-deleted)
- [AWS Config Disabling Channel/Recorder](#aws-config-disabling-channelrecorder)
- [AWS Console GetSigninToken Potential Abuse](#aws-console-getsignintoken-potential-abuse)
- [SES Identity Has Been Deleted](#ses-identity-has-been-deleted)
- [AWS SAML Provider Deletion Activity](#aws-saml-provider-deletion-activity)
- [AWS S3 Bucket Versioning Disable](#aws-s3-bucket-versioning-disable)
- [AWS EC2 Disable EBS Encryption](#aws-ec2-disable-ebs-encryption)
- [AWS Key Pair Import Activity](#aws-key-pair-import-activity)
- [AWS EC2 Startup Shell Script Change](#aws-ec2-startup-shell-script-change)
- [AWS EC2 VM Export Failure](#aws-ec2-vm-export-failure)
- [AWS ECS Task Definition That Queries The Credential Endpoint](#aws-ecs-task-definition-that-queries-the-credential-endpoint)
- [AWS EFS Fileshare Modified or Deleted](#aws-efs-fileshare-modified-or-deleted)
- [AWS EFS Fileshare Mount Modified or Deleted](#aws-efs-fileshare-mount-modified-or-deleted)
- [AWS EKS Cluster Created or Deleted](#aws-eks-cluster-created-or-deleted)
- [AWS ElastiCache Security Group Created](#aws-elasticache-security-group-created)
- [AWS ElastiCache Security Group Modified or Deleted](#aws-elasticache-security-group-modified-or-deleted)
- [Potential Bucket Enumeration on AWS](#potential-bucket-enumeration-on-aws)
- [AWS GuardDuty Important Change](#aws-guardduty-important-change)
- [AWS IAM Backdoor Users Keys](#aws-iam-backdoor-users-keys)
- [AWS IAM S3Browser LoginProfile Creation](#aws-iam-s3browser-loginprofile-creation)
- [AWS IAM S3Browser Templated S3 Bucket Policy Creation](#aws-iam-s3browser-templated-s3-bucket-policy-creation)
- [AWS IAM S3Browser User or AccessKey Creation](#aws-iam-s3browser-user-or-accesskey-creation)
- [AWS KMS Imported Key Material Usage](#aws-kms-imported-key-material-usage)
- [New AWS Lambda Function URL Configuration Created](#new-aws-lambda-function-url-configuration-created)
- [AWS New Lambda Layer Attached](#aws-new-lambda-layer-attached)
- [AWS Glue Development Endpoint Activity](#aws-glue-development-endpoint-activity)
- [AWS RDS Master Password Change](#aws-rds-master-password-change)
- [Modification or Deletion of an AWS RDS Cluster](#modification-or-deletion-of-an-aws-rds-cluster)
- [Restore Public AWS RDS Instance](#restore-public-aws-rds-instance)
- [AWS Root Credentials](#aws-root-credentials)
- [AWS Route 53 Domain Transfer Lock Disabled](#aws-route-53-domain-transfer-lock-disabled)
- [AWS Route 53 Domain Transferred to Another Account](#aws-route-53-domain-transferred-to-another-account)
- [AWS S3 Data Management Tampering](#aws-s3-data-management-tampering)
- [AWS SecurityHub Findings Evasion](#aws-securityhub-findings-evasion)
- [AWS Snapshot Backup Exfiltration](#aws-snapshot-backup-exfiltration)
- [AWS Identity Center Identity Provider Change](#aws-identity-center-identity-provider-change)
- [AWS STS AssumeRole Misuse](#aws-sts-assumerole-misuse)
- [AWS STS GetCallerIdentity Enumeration Via TruffleHog](#aws-sts-getcalleridentity-enumeration-via-trufflehog)
- [AWS STS GetSessionToken Misuse](#aws-sts-getsessiontoken-misuse)
- [AWS Suspicious SAML Activity](#aws-suspicious-saml-activity)
- [AWS User Login Profile Was Modified](#aws-user-login-profile-was-modified)

## AWS Bucket Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `39c9f26d-6e3b-4dbb-9c7a-4154b0281112` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Ivan Saakov, Nasreddine Bencherchali |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_bucket_deleted.yml)**

> Detects the deletion of S3 buckets in AWS CloudTrail logs.
Monitoring the deletion of S3 buckets is critical for security and data integrity, as it may indicate potential data loss or unauthorized access attempts.


```sql
-- ============================================================
-- Title:        AWS Bucket Deleted
-- Sigma ID:     39c9f26d-6e3b-4dbb-9c7a-4154b0281112
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        (none)
-- Author:       Ivan Saakov, Nasreddine Bencherchali
-- Date:         2025-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_bucket_deleted.yml
-- Unmapped:     eventName
-- False Pos:    During maintenance operations or testing, authorized administrators may delete S3 buckets as part of routine data management or cleanup activities.
-- ============================================================
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'DeleteBucket'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** During maintenance operations or testing, authorized administrators may delete S3 buckets as part of routine data management or cleanup activities.

**References:**
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucket.html
- https://awscli.amazonaws.com/v2/documentation/api/latest/reference/s3api/delete-bucket.html

---

## AWS ConsoleLogin Failed Authentication

| Field | Value |
|---|---|
| **Sigma ID** | `6393e346-1977-46ef-8987-ad414a145fad` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1110 |
| **Author** | Ivan Saakov, Nasreddine Bencherchali |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_console_login_failed_authentication.yml)**

> Detects failed AWS console login attempts due to authentication failures. Monitoring these events is crucial for identifying potential brute-force attacks or unauthorized access attempts to AWS accounts.


```sql
-- ============================================================
-- Title:        AWS ConsoleLogin Failed Authentication
-- Sigma ID:     6393e346-1977-46ef-8987-ad414a145fad
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1110
-- Author:       Ivan Saakov, Nasreddine Bencherchali
-- Date:         2025-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_console_login_failed_authentication.yml
-- Unmapped:     eventName, errorMessage
-- False Pos:    Legitimate failed login attempts by authorized users. Investigate the source of repeated failed login attempts.
-- ============================================================
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: errorMessage

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'ConsoleLogin'
    AND rawEventMsg = 'Failed authentication')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate failed login attempts by authorized users. Investigate the source of repeated failed login attempts.

**References:**
- https://naikordian.github.io/blog/posts/brute-force-aws-console/
- https://help.fortinet.com/fsiem/Public_Resource_Access/7_2_1/rules/PH_RULE_AWS_Management_Console_Brute_Force_of_Root_User_Identity.htm
- https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.001/aws_login_failure/aws_cloudtrail_events.json

---

## AWS Successful Console Login Without MFA

| Field | Value |
|---|---|
| **Sigma ID** | `77caf516-34e5-4df9-b4db-20744fea0a60` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | Thuya@Hacktilizer, Ivan Saakov |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_console_login_success_without_mfa.yml)**

> Detects successful AWS console logins that were performed without Multi-Factor Authentication (MFA).
This alert can be used to identify potential unauthorized access attempts, as logging in without MFA can indicate compromised credentials or misconfigured security settings.


```sql
-- ============================================================
-- Title:        AWS Successful Console Login Without MFA
-- Sigma ID:     77caf516-34e5-4df9-b4db-20744fea0a60
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence | T1078.004
-- Author:       Thuya@Hacktilizer, Ivan Saakov
-- Date:         2025-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_console_login_success_without_mfa.yml
-- Unmapped:     eventName, additionalEventData.MFAUsed, responseElements.ConsoleLogin
-- False Pos:    Unlikely
-- ============================================================
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: additionalEventData.MFAUsed
-- UNMAPPED_FIELD: responseElements.ConsoleLogin

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'ConsoleLogin'
    AND rawEventMsg = 'NO'
    AND rawEventMsg = 'Success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unlikely

**References:**
- https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/iam-user-without-mfa/
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html

---

## AWS CloudTrail Important Change

| Field | Value |
|---|---|
| **Sigma ID** | `4db60cc0-36fb-42b7-9b58-a5b53019fb74` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.008 |
| **Author** | vitaliy0x1 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_disable_logging.yml)**

> Detects disabling, deleting and updating of a Trail

```sql
-- ============================================================
-- Title:        AWS CloudTrail Important Change
-- Sigma ID:     4db60cc0-36fb-42b7-9b58-a5b53019fb74
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.008
-- Author:       vitaliy0x1
-- Date:         2020-01-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_disable_logging.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Valid change in a Trail
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'cloudtrail.amazonaws.com'
    AND rawEventMsg IN ('StopLogging', 'UpdateTrail', 'DeleteTrail'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid change in a Trail

**References:**
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html

---

## AWS GuardDuty Detector Deleted Or Updated

| Field | Value |
|---|---|
| **Sigma ID** | `d2656e78-c069-4571-8220-9e0ab5913f19` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001, T1562.008 |
| **Author** | suktech24 |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_guardduty_detector_deleted_or_updated.yml)**

> Detects successful deletion or disabling of an AWS GuardDuty detector, possibly by an attacker trying to avoid detection of its malicious activities.
Upon deletion, GuardDuty stops monitoring the environment and all existing findings are lost.
Verify with the user identity that this activity is legitimate.


```sql
-- ============================================================
-- Title:        AWS GuardDuty Detector Deleted Or Updated
-- Sigma ID:     d2656e78-c069-4571-8220-9e0ab5913f19
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        T1562.001, T1562.008
-- Author:       suktech24
-- Date:         2025-11-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_guardduty_detector_deleted_or_updated.yml
-- Unmapped:     eventSource
-- False Pos:    Legitimate detector deletion by an admin (e.g., during account decommissioning).; Temporary disablement for troubleshooting (verify via change management tickets).; Automated deployment tools (e.g. Terraform) managing GuardDuty state.
-- ============================================================
-- UNMAPPED_FIELD: eventSource

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'guardduty.amazonaws.com'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate detector deletion by an admin (e.g., during account decommissioning).; Temporary disablement for troubleshooting (verify via change management tickets).; Automated deployment tools (e.g. Terraform) managing GuardDuty state.

**References:**
- https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteDetector.html
- https://docs.aws.amazon.com/guardduty/latest/APIReference/API_UpdateDetector.html
- https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_suspend-disable.html
- https://docs.datadoghq.com/security/default_rules/719-39f-9cd/
- https://docs.prismacloud.io/en/enterprise-edition/policy-reference/aws-policies/aws-general-policies/ensure-aws-guardduty-detector-is-enabled
- https://docs.stellarcyber.ai/5.2.x/Using/ML/Alert-Rule-Based-Potentially_Malicious_AWS_Activity.html
- https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Amazon%20Web%20Services/Analytic%20Rules/AWS_GuardDutyDisabled.yaml
- https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/defense_evasion_guardduty_detector_deletion.toml
- https://help.fortinet.com/fsiem/Public_Resource_Access/7_4_0/rules/PH_RULE_AWS_GuardDuty_Detector_Deletion.htm
- https://research.splunk.com/sources/5d8bd475-c8bc-4447-b27f-efa508728b90/
- https://suktech24.com/2025/07/17/aws-threat-detection-rule-guardduty-detector-disabled-or-suspended/
- https://www.atomicredteam.io/atomic-red-team/atomics/T156001#atomic-test-46---aws---guardduty-suspension-or-deletion

---

## Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure

| Field | Value |
|---|---|
| **Sigma ID** | `352a918a-34d8-4882-8470-44830c507aa3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078, T1078.002 |
| **Author** | jamesc-grafana |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_imds_malicious_usage.yml)**

> Detects when an instance identity has taken an action that isn't inside SSM.
This can indicate that a compromised EC2 instance is being used as a pivot point.


```sql
-- ============================================================
-- Title:        Malicious Usage Of IMDS Credentials Outside Of AWS Infrastructure
-- Sigma ID:     352a918a-34d8-4882-8470-44830c507aa3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1078, T1078.002
-- Author:       jamesc-grafana
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_imds_malicious_usage.yml
-- Unmapped:     userIdentity.arn
-- False Pos:    A team has configured an EC2 instance to use instance profiles that grant the option for the EC2 instance to talk to other AWS Services
-- ============================================================
-- UNMAPPED_FIELD: userIdentity.arn

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND match(rawEventMsg, '.+:assumed-role/aws:.+')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A team has configured an EC2 instance to use instance profiles that grant the option for the EC2 instance to talk to other AWS Services

**References:**
- https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-identity-roles.html
- https://ermetic.com/blog/aws/aws-ec2-imds-what-you-need-to-know/
- https://www.packetmischief.ca/2023/07/31/amazon-ec2-credential-exfiltration-how-it-happens-and-how-to-mitigate-it/#lifting-credentials-from-imds-this-is-why-we-cant-have-nice-things

---

## New Network ACL Entry Added

| Field | Value |
|---|---|
| **Sigma ID** | `e1f7febb-7b94-4234-b5c6-00fb8500f5dd` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1562.007 |
| **Author** | jamesc-grafana |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_new_acl_entries.yml)**

> Detects that network ACL entries have been added to a route table which could indicate that new attack vectors have been opened up in the AWS account.


```sql
-- ============================================================
-- Title:        New Network ACL Entry Added
-- Sigma ID:     e1f7febb-7b94-4234-b5c6-00fb8500f5dd
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1562.007
-- Author:       jamesc-grafana
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_new_acl_entries.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Legitimate use of ACLs to enable customer and staff access from the public internet into a public VPC
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'ec2.amazonaws.com'
    AND rawEventMsg = 'CreateNetworkAclEntry')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of ACLs to enable customer and staff access from the public internet into a public VPC

**References:**
- https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/

---

## New Network Route Added

| Field | Value |
|---|---|
| **Sigma ID** | `c803b2ce-c4a2-4836-beae-b112010390b1` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1562.007 |
| **Author** | jamesc-grafana |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_new_route_added.yml)**

> Detects the addition of a new network route to a route table in AWS.


```sql
-- ============================================================
-- Title:        New Network Route Added
-- Sigma ID:     c803b2ce-c4a2-4836-beae-b112010390b1
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1562.007
-- Author:       jamesc-grafana
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_new_route_added.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    New VPC Creation requiring setup of a new route table; New subnets added requiring routing setup
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'ec2.amazonaws.com'
    AND rawEventMsg = 'CreateRoute')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** New VPC Creation requiring setup of a new route table; New subnets added requiring routing setup

**References:**
- https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/

---

## PUA - AWS TruffleHog Execution

| Field | Value |
|---|---|
| **Sigma ID** | `a840e606-7c8c-4684-9bc1-eb6b6155127f` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1555, T1003 |
| **Author** | Swachchhanda Shrawan Poudel (Nextron Systems) |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_pua_trufflehog.yml)**

> Detects the execution of TruffleHog, a popular open-source tool used for scanning repositories for secrets and sensitive information, within an AWS environment.
It has been reported to be used by threat actors for credential harvesting. All detections should be investigated to determine if the usage is authorized by security teams or potentially malicious.


```sql
-- ============================================================
-- Title:        PUA - AWS TruffleHog Execution
-- Sigma ID:     a840e606-7c8c-4684-9bc1-eb6b6155127f
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        T1555, T1003
-- Author:       Swachchhanda Shrawan Poudel (Nextron Systems)
-- Date:         2025-10-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_pua_trufflehog.yml
-- Unmapped:     userAgent
-- False Pos:    Legitimate use of TruffleHog by security teams for credential scanning.
-- ============================================================
-- UNMAPPED_FIELD: userAgent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'TruffleHog'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of TruffleHog by security teams for credential scanning.

**References:**
- https://github.com/trufflesecurity/trufflehog
- https://www.rapid7.com/blog/post/tr-crimson-collective-a-new-threat-group-observed-operating-in-the-cloud/

---

## AWS EnableRegion Command Monitoring

| Field | Value |
|---|---|
| **Sigma ID** | `a5ffb6ea-c784-4e01-b30a-deb6e58ca2ab` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **Author** | Ivan Saakov, Sergey Zelenskiy |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_region_enabled.yml)**

> Detects the use of the EnableRegion command in AWS CloudTrail logs.
While AWS has 30+ regions, some of them are enabled by default, others must be explicitly enabled in each account separately.
There may be situations where security monitoring does not cover some new AWS regions.
Monitoring the EnableRegion command is important for identifying potential persistence mechanisms employed by adversaries, as enabling additional regions can facilitate continued access and operations within an AWS environment.


```sql
-- ============================================================
-- Title:        AWS EnableRegion Command Monitoring
-- Sigma ID:     a5ffb6ea-c784-4e01-b30a-deb6e58ca2ab
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence
-- Author:       Ivan Saakov, Sergey Zelenskiy
-- Date:         2025-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_region_enabled.yml
-- Unmapped:     eventName, eventSource
-- False Pos:    Legitimate use of the EnableRegion command by authorized administrators.
-- ============================================================
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: eventSource

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'EnableRegion'
    AND rawEventMsg = 'account.amazonaws.com')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use of the EnableRegion command by authorized administrators.

**References:**
- https://docs.aws.amazon.com/accounts/latest/reference/API_EnableRegion.html
- https://awscli.amazonaws.com/v2/documentation/api/2.14.0/reference/account/enable-region.html

---

## Ingress/Egress Security Group Modification

| Field | Value |
|---|---|
| **Sigma ID** | `6fb77778-040f-4015-9440-572aa9b6b580` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | jamesc-grafana |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_security_group_change_ingress_egress.yml)**

> Detects when an account makes changes to the ingress or egress rules of a security group.
This can indicate that an attacker is attempting to open up new attack vectors in the account, that they are trying to exfiltrate data over the network, or that they are trying to allow machines in that VPC/Subnet to contact a C&C server.


```sql
-- ============================================================
-- Title:        Ingress/Egress Security Group Modification
-- Sigma ID:     6fb77778-040f-4015-9440-572aa9b6b580
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1190
-- Author:       jamesc-grafana
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_security_group_change_ingress_egress.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    New VPCs and Subnets being setup requiring a different security profile to those already defined; A single port being opened for a new service that is known to be deploying; Administrators closing unused ports to reduce the attack surface
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'ec2.amazonaws.com'
    AND rawEventMsg IN ('AuthorizeSecurityGroupEgress', 'AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'RevokeSecurityGroupIngress'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** New VPCs and Subnets being setup requiring a different security profile to those already defined; A single port being opened for a new service that is known to be deploying; Administrators closing unused ports to reduce the attack surface

**References:**
- https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/

---

## LoadBalancer Security Group Modification

| Field | Value |
|---|---|
| **Sigma ID** | `7a4409fc-f8ca-45f6-8006-127d779eaad9` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | jamesc-grafana |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_security_group_change_loadbalancer.yml)**

> Detects changes to the security groups associated with an Elastic Load Balancer (ELB) or Application Load Balancer (ALB).
This can indicate that a misconfiguration allowing more traffic into the system than required, or could indicate that an attacker is attempting to enable new connections into a VPC or subnet controlled by the account.


```sql
-- ============================================================
-- Title:        LoadBalancer Security Group Modification
-- Sigma ID:     7a4409fc-f8ca-45f6-8006-127d779eaad9
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1190
-- Author:       jamesc-grafana
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_security_group_change_loadbalancer.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Repurposing of an ELB or ALB to serve a different or additional application; Changes to security groups to allow for new services to be deployed
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'elasticloadbalancing.amazonaws.com'
    AND rawEventMsg IN ('ApplySecurityGroupsToLoadBalancer', 'SetSecurityGroups'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Repurposing of an ELB or ALB to serve a different or additional application; Changes to security groups to allow for new services to be deployed

**References:**
- https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/

---

## RDS Database Security Group Modification

| Field | Value |
|---|---|
| **Sigma ID** | `14f3f1c8-02d5-43a2-a191-91ffb52d3015` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1190 |
| **Author** | jamesc-grafana |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_security_group_change_rds.yml)**

> Detects changes to the security group entries for RDS databases.
This can indicate that a misconfiguration has occurred which potentially exposes the database to the public internet, a wider audience within the VPC or that removal of valid rules has occurred which could impact the availability of the database to legitimate services and users.


```sql
-- ============================================================
-- Title:        RDS Database Security Group Modification
-- Sigma ID:     14f3f1c8-02d5-43a2-a191-91ffb52d3015
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1190
-- Author:       jamesc-grafana
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_security_group_change_rds.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Creation of a new Database that needs new security group rules
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'rds.amazonaws.com'
    AND rawEventMsg IN ('AuthorizeDBSecurityGroupIngress', 'CreateDBSecurityGroup', 'DeleteDBSecurityGroup', 'RevokeDBSecurityGroupIngress'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Creation of a new Database that needs new security group rules

**References:**
- https://www.gorillastack.com/blog/real-time-events/important-aws-cloudtrail-security-events-tracking/

---

## Potential Malicious Usage of CloudTrail System Manager

| Field | Value |
|---|---|
| **Sigma ID** | `38e7f511-3f74-41d4-836e-f57dfa18eead` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1566, T1566.002 |
| **Author** | jamesc-grafana |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_ssm_malicious_usage.yml)**

> Detect when System Manager successfully executes commands against an instance.


```sql
-- ============================================================
-- Title:        Potential Malicious Usage of CloudTrail System Manager
-- Sigma ID:     38e7f511-3f74-41d4-836e-f57dfa18eead
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1566, T1566.002
-- Author:       jamesc-grafana
-- Date:         2024-07-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_ssm_malicious_usage.yml
-- Unmapped:     eventName, eventSource
-- False Pos:    There are legitimate uses of SSM to send commands to EC2 instances; Legitimate users may have to use SSM to perform actions against machines in the Cloud to update or maintain them
-- ============================================================
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: eventSource

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'SendCommand'
    AND rawEventMsg = 'ssm.amazonaws.com')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** There are legitimate uses of SSM to send commands to EC2 instances; Legitimate users may have to use SSM to perform actions against machines in the Cloud to update or maintain them

**References:**
- https://github.com/elastic/detection-rules/blob/v8.6.0/rules/integrations/aws/initial_access_via_system_manager.toml

---

## AWS VPC Flow Logs Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `e386b9b5-af12-450e-afff-761730fb8a98` |
| **Level** | high |
| **FSM Severity** | 7 |
| **Author** | Ivan Saakov |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_vpc_flow_logs_deleted.yml)**

> Detects the deletion of one or more VPC Flow Logs in AWS Elastic Compute Cloud (EC2) through the DeleteFlowLogs API call.
Adversaries may delete flow logs to evade detection or remove evidence of network activity, hindering forensic investigations and visibility into malicious operations.


```sql
-- ============================================================
-- Title:        AWS VPC Flow Logs Deleted
-- Sigma ID:     e386b9b5-af12-450e-afff-761730fb8a98
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        (none)
-- Author:       Ivan Saakov
-- Date:         2025-10-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_cloudtrail_vpc_flow_logs_deleted.yml
-- Unmapped:     eventName
-- False Pos:    During maintenance operations or testing, authorized administrators may delete VPC Flow Logs as part of routine network management or cleanup activities.
-- ============================================================
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND rawEventMsg = 'DeleteFlowLogs'
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** During maintenance operations or testing, authorized administrators may delete VPC Flow Logs as part of routine network management or cleanup activities.

**References:**
- https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.html
- https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/delete-flow-logs.html
- https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/integrations/aws/defense_evasion_ec2_flow_log_deletion

---

## AWS Config Disabling Channel/Recorder

| Field | Value |
|---|---|
| **Sigma ID** | `07330162-dba1-4746-8121-a9647d49d297` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.008 |
| **Author** | vitaliy0x1 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_config_disable_recording.yml)**

> Detects AWS Config Service disabling

```sql
-- ============================================================
-- Title:        AWS Config Disabling Channel/Recorder
-- Sigma ID:     07330162-dba1-4746-8121-a9647d49d297
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.008
-- Author:       vitaliy0x1
-- Date:         2020-01-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_config_disable_recording.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Valid change in AWS Config Service
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'config.amazonaws.com'
    AND rawEventMsg IN ('DeleteDeliveryChannel', 'StopConfigurationRecorder'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid change in AWS Config Service

**References:**
- https://docs.aws.amazon.com/config/latest/developerguide/cloudtrail-log-files-for-aws-config.html

---

## AWS Console GetSigninToken Potential Abuse

| Field | Value |
|---|---|
| **Sigma ID** | `f8103686-e3e8-46f3-be72-65f7fcb4aa53` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1021.007, T1550.001 |
| **Author** | Chester Le Bron (@123Le_Bron) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_console_getsignintoken.yml)**

> Detects potentially suspicious events involving "GetSigninToken".
An adversary using the "aws_consoler" tool can leverage this console API to create temporary federated credential that help obfuscate which AWS credential is compromised (the original access key) and enables the adversary to pivot from the AWS CLI to console sessions without the need for MFA using the new access key issued in this request.


```sql
-- ============================================================
-- Title:        AWS Console GetSigninToken Potential Abuse
-- Sigma ID:     f8103686-e3e8-46f3-be72-65f7fcb4aa53
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1021.007, T1550.001
-- Author:       Chester Le Bron (@123Le_Bron)
-- Date:         2024-02-26
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_console_getsignintoken.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    GetSigninToken events will occur when using AWS SSO portal to login and will generate false positives if you do not filter for the expected user agent(s), see filter. Non-SSO configured roles would be abnormal and should be investigated.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'signin.amazonaws.com'
    AND rawEventMsg = 'GetSigninToken')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** GetSigninToken events will occur when using AWS SSO portal to login and will generate false positives if you do not filter for the expected user agent(s), see filter. Non-SSO configured roles would be abnormal and should be investigated.

**References:**
- https://github.com/NetSPI/aws_consoler
- https://www.crowdstrike.com/blog/analysis-of-intrusion-campaign-targeting-telecom-and-bpo-companies/

---

## SES Identity Has Been Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `20f754db-d025-4a8f-9d74-e0037e999a9a` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Techniques** | T1070 |
| **Author** | Janantha Marasinghe |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_delete_identity.yml)**

> Detects an instance of an SES identity being deleted via the "DeleteIdentity" event. This may be an indicator of an adversary removing the account that carried out suspicious or malicious activities

```sql
-- ============================================================
-- Title:        SES Identity Has Been Deleted
-- Sigma ID:     20f754db-d025-4a8f-9d74-e0037e999a9a
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        T1070
-- Author:       Janantha Marasinghe
-- Date:         2022-12-13
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_delete_identity.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'ses.amazonaws.com'
    AND rawEventMsg = 'DeleteIdentity')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/

---

## AWS SAML Provider Deletion Activity

| Field | Value |
|---|---|
| **Sigma ID** | `ccd6a6c8-bb4e-4a91-9d2a-07e632819374` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence, impact |
| **MITRE Techniques** | T1078.004, T1531 |
| **Author** | Ivan Saakov |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_delete_saml_provider.yml)**

> Detects the deletion of an AWS SAML provider, potentially indicating malicious intent to disrupt administrative or security team access.
An attacker can remove the SAML provider for the information security team or a team of system administrators, to make it difficult for them to work and investigate at the time of the attack and after it.


```sql
-- ============================================================
-- Title:        AWS SAML Provider Deletion Activity
-- Sigma ID:     ccd6a6c8-bb4e-4a91-9d2a-07e632819374
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence, impact | T1078.004, T1531
-- Author:       Ivan Saakov
-- Date:         2024-12-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_delete_saml_provider.yml
-- Unmapped:     eventSource, eventName, status
-- False Pos:    Automated processes using tools like Terraform may trigger this alert.; Legitimate administrative actions by authorized system administrators could cause this alert. Verify the user identity, user agent, and hostname to ensure they are expected.; Deletions by unfamiliar users should be investigated. If the behavior is known and expected, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: status

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'iam.amazonaws.com'
    AND rawEventMsg = 'DeleteSAMLProvider'
    AND rawEventMsg = 'success')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Automated processes using tools like Terraform may trigger this alert.; Legitimate administrative actions by authorized system administrators could cause this alert. Verify the user identity, user agent, and hostname to ensure they are expected.; Deletions by unfamiliar users should be investigated. If the behavior is known and expected, it can be exempted from the rule.

**References:**
- https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteSAMLProvider.html

---

## AWS S3 Bucket Versioning Disable

| Field | Value |
|---|---|
| **Sigma ID** | `a136ac98-b2bc-4189-a14d-f0d0388e57a7` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1490 |
| **Author** | Sean Johnstone \| Unit 42 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_disable_bucket_versioning.yml)**

> Detects when S3 bucket versioning is disabled. Threat actors use this technique during AWS ransomware incidents prior to deleting S3 objects.

```sql
-- ============================================================
-- Title:        AWS S3 Bucket Versioning Disable
-- Sigma ID:     a136ac98-b2bc-4189-a14d-f0d0388e57a7
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1490
-- Author:       Sean Johnstone | Unit 42
-- Date:         2023-10-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_disable_bucket_versioning.yml
-- Unmapped:     eventSource, eventName, requestParameters
-- False Pos:    AWS administrator legitimately disabling bucket versioning
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: requestParameters

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 's3.amazonaws.com'
    AND rawEventMsg = 'PutBucketVersioning'
    AND rawEventMsg LIKE '%Suspended%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** AWS administrator legitimately disabling bucket versioning

**References:**
- https://invictus-ir.medium.com/ransomware-in-the-cloud-7f14805bbe82

---

## AWS EC2 Disable EBS Encryption

| Field | Value |
|---|---|
| **Sigma ID** | `16124c2d-e40b-4fcc-8f2c-5ab7870a2223` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1486, T1565 |
| **Author** | Sittikorn S |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_ec2_disable_encryption.yml)**

> Identifies disabling of default Amazon Elastic Block Store (EBS) encryption in the current region.
Disabling default encryption does not change the encryption status of your existing volumes.


```sql
-- ============================================================
-- Title:        AWS EC2 Disable EBS Encryption
-- Sigma ID:     16124c2d-e40b-4fcc-8f2c-5ab7870a2223
-- Level:        medium  |  FSM Severity: 5
-- Status:       stable
-- MITRE:        impact | T1486, T1565
-- Author:       Sittikorn S
-- Date:         2021-06-29
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_ec2_disable_encryption.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    System Administrator Activities; DEV, UAT, SAT environment. You should apply this rule with PROD account only.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'ec2.amazonaws.com'
    AND rawEventMsg = 'DisableEbsEncryptionByDefault')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** System Administrator Activities; DEV, UAT, SAT environment. You should apply this rule with PROD account only.

**References:**
- https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.html

---

## AWS Key Pair Import Activity

| Field | Value |
|---|---|
| **Sigma ID** | `92f84194-8d9a-4ee0-8699-c30bfac59780` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078 |
| **Author** | Ivan Saakov |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_ec2_import_key_pair_activity.yml)**

> Detects the import of SSH key pairs into AWS EC2, which may indicate an attacker attempting to gain unauthorized access to instances. This activity could lead to initial access, persistence, or privilege escalation, potentially compromising sensitive data and operations.


```sql
-- ============================================================
-- Title:        AWS Key Pair Import Activity
-- Sigma ID:     92f84194-8d9a-4ee0-8699-c30bfac59780
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        persistence | T1078
-- Author:       Ivan Saakov
-- Date:         2024-12-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_ec2_import_key_pair_activity.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Legitimate administrative actions by authorized users importing keys for valid purposes.; Automated processes for infrastructure setup may trigger this alert.; Verify the user identity, user agent, and source IP address to ensure they are expected.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'ec2.amazonaws.com'
    AND rawEventMsg = 'ImportKeyPair')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate administrative actions by authorized users importing keys for valid purposes.; Automated processes for infrastructure setup may trigger this alert.; Verify the user identity, user agent, and source IP address to ensure they are expected.

**References:**
- https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ImportKeyPair.html

---

## AWS EC2 Startup Shell Script Change

| Field | Value |
|---|---|
| **Sigma ID** | `1ab3c5ed-5baf-417b-bb6b-78ca33f6c3df` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution |
| **MITRE Techniques** | T1059.001, T1059.003, T1059.004 |
| **Author** | faloker |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_ec2_startup_script_change.yml)**

> Detects changes to the EC2 instance startup script. The shell script will be executed as root/SYSTEM every time the specific instances are booted up.

```sql
-- ============================================================
-- Title:        AWS EC2 Startup Shell Script Change
-- Sigma ID:     1ab3c5ed-5baf-417b-bb6b-78ca33f6c3df
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution | T1059.001, T1059.003, T1059.004
-- Author:       faloker
-- Date:         2020-02-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_ec2_startup_script_change.yml
-- Unmapped:     eventSource, requestParameters.attribute, eventName
-- False Pos:    Valid changes to the startup script
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: requestParameters.attribute
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'ec2.amazonaws.com'
    AND rawEventMsg = 'userData'
    AND rawEventMsg = 'ModifyInstanceAttribute')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid changes to the startup script

**References:**
- https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/ec2__startup_shell_script/main.py#L9

---

## AWS EC2 VM Export Failure

| Field | Value |
|---|---|
| **Sigma ID** | `54b9a76a-3c71-4673-b4b3-2edb4566ea7b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | collection, exfiltration |
| **MITRE Techniques** | T1005, T1537 |
| **Author** | Diogo Braz |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_ec2_vm_export_failure.yml)**

> An attempt to export an AWS EC2 instance has been detected. A VM Export might indicate an attempt to extract information from an instance.

```sql
-- ============================================================
-- Title:        AWS EC2 VM Export Failure
-- Sigma ID:     54b9a76a-3c71-4673-b4b3-2edb4566ea7b
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        collection, exfiltration | T1005, T1537
-- Author:       Diogo Braz
-- Date:         2020-04-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_ec2_vm_export_failure.yml
-- Unmapped:     eventName, eventSource
-- False Pos:    (none)
-- ============================================================
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: eventSource

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'CreateInstanceExportTask'
    AND rawEventMsg = 'ec2.amazonaws.com')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**References:**
- https://docs.aws.amazon.com/vm-import/latest/userguide/vmexport.html#export-instance

---

## AWS ECS Task Definition That Queries The Credential Endpoint

| Field | Value |
|---|---|
| **Sigma ID** | `b94bf91e-c2bf-4047-9c43-c6810f43baad` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1525 |
| **Author** | Darin Smith |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_ecs_task_definition_cred_endpoint_query.yml)**

> Detects when an Elastic Container Service (ECS) Task Definition includes a command to query the credential endpoint.
This can indicate a potential adversary adding a backdoor to establish persistence or escalate privileges.


```sql
-- ============================================================
-- Title:        AWS ECS Task Definition That Queries The Credential Endpoint
-- Sigma ID:     b94bf91e-c2bf-4047-9c43-c6810f43baad
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1525
-- Author:       Darin Smith
-- Date:         2022-06-07
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_ecs_task_definition_cred_endpoint_query.yml
-- Unmapped:     eventSource, eventName, requestParameters.containerDefinitions.command
-- False Pos:    Task Definition being modified to request credentials from the Task Metadata Service for valid reasons
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: requestParameters.containerDefinitions.command

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'ecs.amazonaws.com'
    AND rawEventMsg IN ('DescribeTaskDefinition', 'RegisterTaskDefinition', 'RunTask')
    AND rawEventMsg LIKE '%$AWS\_CONTAINER\_CREDENTIALS\_RELATIVE\_URI%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Task Definition being modified to request credentials from the Task Metadata Service for valid reasons

**References:**
- https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/ecs__backdoor_task_def/main.py
- https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RegisterTaskDefinition.html
- https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html

---

## AWS EFS Fileshare Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `25cb1ba1-8a19-4a23-a198-d252664c8cef` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_efs_fileshare_modified_or_deleted.yml)**

> Detects when a EFS Fileshare is modified or deleted.
You can't delete a file system that is in use.
If the file system has any mount targets, the adversary must first delete them, so deletion of a mount will occur before deletion of a fileshare.


```sql
-- ============================================================
-- Title:        AWS EFS Fileshare Modified or Deleted
-- Sigma ID:     25cb1ba1-8a19-4a23-a198-d252664c8cef
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_efs_fileshare_modified_or_deleted.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'elasticfilesystem.amazonaws.com'
    AND rawEventMsg = 'DeleteFileSystem')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://docs.aws.amazon.com/efs/latest/ug/API_DeleteFileSystem.html

---

## AWS EFS Fileshare Mount Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `6a7ba45c-63d8-473e-9736-2eaabff79964` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1485 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_efs_fileshare_mount_modified_or_deleted.yml)**

> Detects when a EFS Fileshare Mount is modified or deleted. An adversary breaking any file system using the mount target that is being deleted, which might disrupt instances or applications using those mounts.

```sql
-- ============================================================
-- Title:        AWS EFS Fileshare Mount Modified or Deleted
-- Sigma ID:     6a7ba45c-63d8-473e-9736-2eaabff79964
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        impact | T1485
-- Author:       Austin Songer @austinsonger
-- Date:         2021-08-15
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_efs_fileshare_mount_modified_or_deleted.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'elasticfilesystem.amazonaws.com'
    AND rawEventMsg = 'DeleteMountTarget')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://docs.aws.amazon.com/efs/latest/ug/API_DeleteMountTarget.html

---

## AWS EKS Cluster Created or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `33d50d03-20ec-4b74-a74e-1e65a38af1c0` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1485 |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_eks_cluster_created_or_deleted.yml)**

> Identifies when an EKS cluster is created or deleted.

```sql
-- ============================================================
-- Title:        AWS EKS Cluster Created or Deleted
-- Sigma ID:     33d50d03-20ec-4b74-a74e-1e65a38af1c0
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact | T1485
-- Author:       Austin Songer
-- Date:         2021-08-16
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_eks_cluster_created_or_deleted.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    EKS Cluster being created or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; EKS Cluster created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'eks.amazonaws.com'
    AND rawEventMsg IN ('CreateCluster', 'DeleteCluster'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** EKS Cluster being created or deleted may be performed by a system administrator.; Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; EKS Cluster created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://any-api.com/amazonaws_com/eks/docs/API_Description

---

## AWS ElastiCache Security Group Created

| Field | Value |
|---|---|
| **Sigma ID** | `4ae68615-866f-4304-b24b-ba048dfa5ca7` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1136, T1136.003 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_elasticache_security_group_created.yml)**

> Detects when an ElastiCache security group has been created.

```sql
-- ============================================================
-- Title:        AWS ElastiCache Security Group Created
-- Sigma ID:     4ae68615-866f-4304-b24b-ba048dfa5ca7
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1136, T1136.003
-- Author:       Austin Songer @austinsonger
-- Date:         2021-07-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_elasticache_security_group_created.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    A ElastiCache security group may be created by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Security group creations from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'elasticache.amazonaws.com'
    AND rawEventMsg = 'CreateCacheSecurityGroup')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A ElastiCache security group may be created by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Security group creations from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://github.com/elastic/detection-rules/blob/598f3d7e0a63221c0703ad9a0ea7e22e7bc5961e/rules/integrations/aws/persistence_elasticache_security_group_creation.toml

---

## AWS ElastiCache Security Group Modified or Deleted

| Field | Value |
|---|---|
| **Sigma ID** | `7c797da2-9cf2-4523-ba64-33b06339f0cc` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1531 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_elasticache_security_group_modified_or_deleted.yml)**

> Identifies when an ElastiCache security group has been modified or deleted.

```sql
-- ============================================================
-- Title:        AWS ElastiCache Security Group Modified or Deleted
-- Sigma ID:     7c797da2-9cf2-4523-ba64-33b06339f0cc
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        impact | T1531
-- Author:       Austin Songer @austinsonger
-- Date:         2021-07-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_elasticache_security_group_modified_or_deleted.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    A ElastiCache security group deletion may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Security Group deletions from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'elasticache.amazonaws.com'
    AND rawEventMsg IN ('DeleteCacheSecurityGroup', 'AuthorizeCacheSecurityGroupIngress', 'RevokeCacheSecurityGroupIngress', 'AuthorizeCacheSecurityGroupEgress', 'RevokeCacheSecurityGroupEgress'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A ElastiCache security group deletion may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Security Group deletions from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://github.com/elastic/detection-rules/blob/7d5efd68603f42be5e125b5a6a503b2ef3ac0f4e/rules/integrations/aws/impact_elasticache_security_group_modified_or_deleted.toml

---

## Potential Bucket Enumeration on AWS

| Field | Value |
|---|---|
| **Sigma ID** | `f305fd62-beca-47da-ad95-7690a0620084` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1580, T1619 |
| **Author** | Christopher Peacock @securepeacock, SCYTHE @scythe_io |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_enum_buckets.yml)**

> Looks for potential enumeration of AWS buckets via ListBuckets.

```sql
-- ============================================================
-- Title:        Potential Bucket Enumeration on AWS
-- Sigma ID:     f305fd62-beca-47da-ad95-7690a0620084
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        discovery | T1580, T1619
-- Author:       Christopher Peacock @securepeacock, SCYTHE @scythe_io
-- Date:         2023-01-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_enum_buckets.yml
-- Unmapped:     eventSource, eventName, userIdentity.type
-- False Pos:    Administrators listing buckets, it may be necessary to filter out users who commonly conduct this activity.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: userIdentity.type

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 's3.amazonaws.com'
    AND rawEventMsg = 'ListBuckets')
  AND NOT (rawEventMsg = 'AssumedRole'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Administrators listing buckets, it may be necessary to filter out users who commonly conduct this activity.

**References:**
- https://github.com/Lifka/hacking-resources/blob/c2ae355d381bd0c9f0b32c4ead049f44e5b1573f/cloud-hacking-cheat-sheets.md
- https://jamesonhacking.blogspot.com/2020/12/pivoting-to-private-aws-s3-buckets.html
- https://securitycafe.ro/2022/12/14/aws-enumeration-part-ii-practical-enumeration/

---

## AWS GuardDuty Important Change

| Field | Value |
|---|---|
| **Sigma ID** | `6e61ee20-ce00-4f8d-8aee-bedd8216f7e3` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562.001 |
| **Author** | faloker |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_guardduty_disruption.yml)**

> Detects updates of the GuardDuty list of trusted IPs, perhaps to disable security alerts against malicious IPs.

```sql
-- ============================================================
-- Title:        AWS GuardDuty Important Change
-- Sigma ID:     6e61ee20-ce00-4f8d-8aee-bedd8216f7e3
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        T1562.001
-- Author:       faloker
-- Date:         2020-02-11
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_guardduty_disruption.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Valid change in the GuardDuty (e.g. to ignore internal scanners)
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'guardduty.amazonaws.com'
    AND rawEventMsg = 'CreateIPSet')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid change in the GuardDuty (e.g. to ignore internal scanners)

**References:**
- https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/guardduty__whitelist_ip/main.py#L9

---

## AWS IAM Backdoor Users Keys

| Field | Value |
|---|---|
| **Sigma ID** | `0a5177f4-6ca9-44c2-aacf-d3f3d8b6e4d2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | faloker |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_iam_backdoor_users_keys.yml)**

> Detects AWS API key creation for a user by another user.
Backdoored users can be used to obtain persistence in the AWS environment.
Also with this alert, you can detect a flow of AWS keys in your org.


```sql
-- ============================================================
-- Title:        AWS IAM Backdoor Users Keys
-- Sigma ID:     0a5177f4-6ca9-44c2-aacf-d3f3d8b6e4d2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       faloker
-- Date:         2020-02-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_iam_backdoor_users_keys.yml
-- Unmapped:     eventSource, eventName, userIdentity.arn
-- False Pos:    Adding user keys to their own accounts (the filter cannot cover all possible variants of user naming); AWS API keys legitimate exchange workflows
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: userIdentity.arn

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND ((rawEventMsg = 'iam.amazonaws.com'
    AND rawEventMsg = 'CreateAccessKey')
  AND NOT (rawEventMsg LIKE '%responseElements.accessKey.userName%'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Adding user keys to their own accounts (the filter cannot cover all possible variants of user naming); AWS API keys legitimate exchange workflows

**References:**
- https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/iam__backdoor_users_keys/main.py

---

## AWS IAM S3Browser LoginProfile Creation

| Field | Value |
|---|---|
| **Sigma ID** | `db014773-b1d3-46bd-ba26-133337c0ffee` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1059.009, T1078.004 |
| **Author** | daniel.bohannon@permiso.io (@danielhbohannon) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_iam_s3browser_loginprofile_creation.yml)**

> Detects S3 Browser utility performing reconnaissance looking for existing IAM Users without a LoginProfile defined then (when found) creating a LoginProfile.

```sql
-- ============================================================
-- Title:        AWS IAM S3Browser LoginProfile Creation
-- Sigma ID:     db014773-b1d3-46bd-ba26-133337c0ffee
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1059.009, T1078.004
-- Author:       daniel.bohannon@permiso.io (@danielhbohannon)
-- Date:         2023-05-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_iam_s3browser_loginprofile_creation.yml
-- Unmapped:     eventSource, eventName, userAgent
-- False Pos:    Valid usage of S3 Browser for IAM LoginProfile listing and/or creation
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: userAgent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'iam.amazonaws.com'
    AND rawEventMsg IN ('GetLoginProfile', 'CreateLoginProfile')
    AND rawEventMsg LIKE '%S3 Browser%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid usage of S3 Browser for IAM LoginProfile listing and/or creation

**References:**
- https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor

---

## AWS IAM S3Browser Templated S3 Bucket Policy Creation

| Field | Value |
|---|---|
| **Sigma ID** | `db014773-7375-4f4e-b83b-133337c0ffee` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1059.009, T1078.004 |
| **Author** | daniel.bohannon@permiso.io (@danielhbohannon) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_iam_s3browser_templated_s3_bucket_policy_creation.yml)**

> Detects S3 browser utility creating Inline IAM policy containing default S3 bucket name placeholder value of "<YOUR-BUCKET-NAME>".

```sql
-- ============================================================
-- Title:        AWS IAM S3Browser Templated S3 Bucket Policy Creation
-- Sigma ID:     db014773-7375-4f4e-b83b-133337c0ffee
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1059.009, T1078.004
-- Author:       daniel.bohannon@permiso.io (@danielhbohannon)
-- Date:         2023-05-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_iam_s3browser_templated_s3_bucket_policy_creation.yml
-- Unmapped:     eventSource, eventName, userAgent, requestParameters
-- False Pos:    Valid usage of S3 browser with accidental creation of default Inline IAM policy without changing default S3 bucket name placeholder value
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: userAgent
-- UNMAPPED_FIELD: requestParameters

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'iam.amazonaws.com'
    AND rawEventMsg = 'PutUserPolicy'
    AND rawEventMsg LIKE '%S3 Browser%'
    AND rawEventMsg LIKE '%"arn:aws:s3:::<YOUR-BUCKET-NAME>/*"%' AND rawEventMsg LIKE '%"s3:GetObject"%' AND rawEventMsg LIKE '%"Allow"%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid usage of S3 browser with accidental creation of default Inline IAM policy without changing default S3 bucket name placeholder value

**References:**
- https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor

---

## AWS IAM S3Browser User or AccessKey Creation

| Field | Value |
|---|---|
| **Sigma ID** | `db014773-d9d9-4792-91e5-133337c0ffee` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | execution, persistence |
| **MITRE Techniques** | T1059.009, T1078.004 |
| **Author** | daniel.bohannon@permiso.io (@danielhbohannon) |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_iam_s3browser_user_or_accesskey_creation.yml)**

> Detects S3 Browser utility creating IAM User or AccessKey.

```sql
-- ============================================================
-- Title:        AWS IAM S3Browser User or AccessKey Creation
-- Sigma ID:     db014773-d9d9-4792-91e5-133337c0ffee
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        execution, persistence | T1059.009, T1078.004
-- Author:       daniel.bohannon@permiso.io (@danielhbohannon)
-- Date:         2023-05-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_iam_s3browser_user_or_accesskey_creation.yml
-- Unmapped:     eventSource, eventName, userAgent
-- False Pos:    Valid usage of S3 Browser for IAM User and/or AccessKey creation
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: userAgent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'iam.amazonaws.com'
    AND rawEventMsg IN ('CreateUser', 'CreateAccessKey')
    AND rawEventMsg LIKE '%S3 Browser%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid usage of S3 Browser for IAM User and/or AccessKey creation

**References:**
- https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor

---

## AWS KMS Imported Key Material Usage

| Field | Value |
|---|---|
| **Sigma ID** | `1279262f-1464-422f-ac0d-5b545320c526` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | impact |
| **MITRE Techniques** | T1486, T1608.003 |
| **Author** | toopricey |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_kms_import_key_material.yml)**

> Detects the import or deletion of key material in AWS KMS, which can be used as part of ransomware attacks. This activity is uncommon and provides a high certainty signal.


```sql
-- ============================================================
-- Title:        AWS KMS Imported Key Material Usage
-- Sigma ID:     1279262f-1464-422f-ac0d-5b545320c526
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        impact | T1486, T1608.003
-- Author:       toopricey
-- Date:         2025-10-18
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_kms_import_key_material.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Legitimate use cases for imported key material are rare, but may include, Organizations with hybrid cloud architectures that import external key material for compliance requirements.; Development or testing environments that simulate external key management scenarios. Even in these cases, such activity is typically infrequent and should not add significant noise.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'kms.amazonaws.com'
    AND rawEventMsg IN ('ImportKeyMaterial', 'DeleteImportedKeyMaterial'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate use cases for imported key material are rare, but may include, Organizations with hybrid cloud architectures that import external key material for compliance requirements.; Development or testing environments that simulate external key management scenarios. Even in these cases, such activity is typically infrequent and should not add significant noise.

**References:**
- https://www.chrisfarris.com/post/effective-aws-ransomware/
- https://docs.aws.amazon.com/kms/latest/developerguide/ct-importkeymaterial.html
- https://docs.aws.amazon.com/kms/latest/developerguide/ct-deleteimportedkeymaterial.html

---

## New AWS Lambda Function URL Configuration Created

| Field | Value |
|---|---|
| **Sigma ID** | `ec541962-c05a-4420-b9ea-84de072d18f4` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **Author** | Ivan Saakov |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_lambda_function_url.yml)**

> Detects when a user creates a Lambda function URL configuration, which could be used to expose the function to the internet and potentially allow unauthorized access to the function's IAM role for AWS API calls.
This could give an adversary access to the privileges associated with the Lambda service role that is attached to that function.


```sql
-- ============================================================
-- Title:        New AWS Lambda Function URL Configuration Created
-- Sigma ID:     ec541962-c05a-4420-b9ea-84de072d18f4
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        (none)
-- Author:       Ivan Saakov
-- Date:         2024-12-19
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_lambda_function_url.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Creating a Lambda function URL configuration may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Creating a Lambda function URL configuration from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'lambda.amazonaws.com'
    AND rawEventMsg = 'CreateFunctionUrlConfig')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Creating a Lambda function URL configuration may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Creating a Lambda function URL configuration from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://docs.aws.amazon.com/lambda/latest/dg/API_CreateFunctionUrlConfig.html
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-lambda-privesc
- https://www.wiz.io/blog/how-to-set-secure-defaults-on-aws

---

## AWS New Lambda Layer Attached

| Field | Value |
|---|---|
| **Sigma ID** | `97fbabf8-8e1b-47a2-b7d5-a418d2b95e3d` |
| **Level** | low |
| **FSM Severity** | 3 |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_new_lambda_layer_attached.yml)**

> Detects when a user attached a Lambda layer to an existing Lambda function.
A malicious Lambda layer could execute arbitrary code in the context of the function's IAM role.
This would give an adversary access to resources that the function has access to.


```sql
-- ============================================================
-- Title:        AWS New Lambda Layer Attached
-- Sigma ID:     97fbabf8-8e1b-47a2-b7d5-a418d2b95e3d
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        (none)
-- Author:       Austin Songer
-- Date:         2021-09-23
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_new_lambda_layer_attached.yml
-- Unmapped:     eventSource, eventName, requestParameters.layers
-- False Pos:    Lambda Layer being attached may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Lambda Layer being attached from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: requestParameters.layers

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'lambda.amazonaws.com'
    AND rawEventMsg LIKE 'UpdateFunctionConfiguration%'
    AND rawEventMsg LIKE '%*%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Lambda Layer being attached may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; Lambda Layer being attached from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://docs.aws.amazon.com/lambda/latest/dg/API_UpdateFunctionConfiguration.html
- https://github.com/clearvector/lambda-spy

---

## AWS Glue Development Endpoint Activity

| Field | Value |
|---|---|
| **Sigma ID** | `4990c2e3-f4b8-45e3-bc3c-30b14ff0ed26` |
| **Level** | low |
| **FSM Severity** | 3 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_passed_role_to_glue_development_endpoint.yml)**

> Detects possible suspicious glue development endpoint activity.

```sql
-- ============================================================
-- Title:        AWS Glue Development Endpoint Activity
-- Sigma ID:     4990c2e3-f4b8-45e3-bc3c-30b14ff0ed26
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        (none)
-- Author:       Austin Songer @austinsonger
-- Date:         2021-10-03
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_passed_role_to_glue_development_endpoint.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Glue Development Endpoint Activity may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'glue.amazonaws.com'
    AND rawEventMsg IN ('CreateDevEndpoint', 'DeleteDevEndpoint', 'UpdateDevEndpoint'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Glue Development Endpoint Activity may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- https://docs.aws.amazon.com/glue/latest/webapi/API_CreateDevEndpoint.html

---

## AWS RDS Master Password Change

| Field | Value |
|---|---|
| **Sigma ID** | `8a63cdd4-6207-414a-85bc-7e032bd3c1a2` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1020 |
| **Author** | faloker |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_rds_change_master_password.yml)**

> Detects the change of database master password. It may be a part of data exfiltration.

```sql
-- ============================================================
-- Title:        AWS RDS Master Password Change
-- Sigma ID:     8a63cdd4-6207-414a-85bc-7e032bd3c1a2
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1020
-- Author:       faloker
-- Date:         2020-02-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_rds_change_master_password.yml
-- Unmapped:     eventSource, responseElements.pendingModifiedValues.masterUserPassword, eventName
-- False Pos:    Benign changes to a db instance
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: responseElements.pendingModifiedValues.masterUserPassword
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'rds.amazonaws.com'
    AND rawEventMsg LIKE '%*%'
    AND rawEventMsg = 'ModifyDBInstance')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Benign changes to a db instance

**References:**
- https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/rds__explore_snapshots/main.py

---

## Modification or Deletion of an AWS RDS Cluster

| Field | Value |
|---|---|
| **Sigma ID** | `457cc9ac-d8e6-4d1d-8c0e-251d0f11a74c` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1020 |
| **Author** | Ivan Saakov |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_rds_dbcluster_actions.yml)**

> Detects modifications to an RDS cluster or its deletion, which may indicate potential data exfiltration attempts, unauthorized access, or exposure of sensitive information.

```sql
-- ============================================================
-- Title:        Modification or Deletion of an AWS RDS Cluster
-- Sigma ID:     457cc9ac-d8e6-4d1d-8c0e-251d0f11a74c
-- Level:        high  |  FSM Severity: 7
-- Status:       experimental
-- MITRE:        exfiltration | T1020
-- Author:       Ivan Saakov
-- Date:         2024-12-06
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_rds_dbcluster_actions.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Verify if the modification or deletion was performed by an authorized administrator.; Confirm if the modification or deletion was part of a planned change or maintenance activity.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'rds.amazonaws.com'
    AND rawEventMsg IN ('ModifyDBCluster', 'DeleteDBCluster'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Verify if the modification or deletion was performed by an authorized administrator.; Confirm if the modification or deletion was part of a planned change or maintenance activity.

**References:**
- https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_ModifyDBCluster.html
- https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DeleteDBCluster.html
- https://cloud.hacktricks.xyz/pentesting-cloud/aws-security/aws-privilege-escalation/aws-rds-privesc#rds-modifydbinstance

---

## Restore Public AWS RDS Instance

| Field | Value |
|---|---|
| **Sigma ID** | `c3f265c7-ff03-4056-8ab2-d486227b4599` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1020 |
| **Author** | faloker |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_rds_public_db_restore.yml)**

> Detects the recovery of a new public database instance from a snapshot. It may be a part of data exfiltration.

```sql
-- ============================================================
-- Title:        Restore Public AWS RDS Instance
-- Sigma ID:     c3f265c7-ff03-4056-8ab2-d486227b4599
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        exfiltration | T1020
-- Author:       faloker
-- Date:         2020-02-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_rds_public_db_restore.yml
-- Unmapped:     eventSource, responseElements.publiclyAccessible, eventName
-- False Pos:    Unknown
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: responseElements.publiclyAccessible
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'rds.amazonaws.com'
    AND rawEventMsg = 'true'
    AND rawEventMsg = 'RestoreDBInstanceFromDBSnapshot')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Unknown

**References:**
- https://github.com/RhinoSecurityLabs/pacu/blob/866376cd711666c775bbfcde0524c817f2c5b181/pacu/modules/rds__explore_snapshots/main.py

---

## AWS Root Credentials

| Field | Value |
|---|---|
| **Sigma ID** | `8ad1600d-e9dc-4251-b0ee-a65268f29add` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078.004 |
| **Author** | vitaliy0x1 |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_root_account_usage.yml)**

> Detects AWS root account usage

```sql
-- ============================================================
-- Title:        AWS Root Credentials
-- Sigma ID:     8ad1600d-e9dc-4251-b0ee-a65268f29add
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078.004
-- Author:       vitaliy0x1
-- Date:         2020-01-21
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_root_account_usage.yml
-- Unmapped:     userIdentity.type, eventType
-- False Pos:    AWS Tasks That Require AWS Account Root User Credentials https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html
-- ============================================================
-- UNMAPPED_FIELD: userIdentity.type
-- UNMAPPED_FIELD: eventType

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'Root'
  AND NOT (rawEventMsg = 'AwsServiceEvent'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** AWS Tasks That Require AWS Account Root User Credentials https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html

**References:**
- https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html

---

## AWS Route 53 Domain Transfer Lock Disabled

| Field | Value |
|---|---|
| **Sigma ID** | `3940b5f1-3f46-44aa-b746-ebe615b879e0` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Elastic, Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_route_53_domain_transferred_lock_disabled.yml)**

> Detects when a transfer lock was removed from a Route 53 domain. It is recommended to refrain from performing this action unless intending to transfer the domain to a different registrar.

```sql
-- ============================================================
-- Title:        AWS Route 53 Domain Transfer Lock Disabled
-- Sigma ID:     3940b5f1-3f46-44aa-b746-ebe615b879e0
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       Elastic, Austin Songer @austinsonger
-- Date:         2021-07-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_route_53_domain_transferred_lock_disabled.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    A domain transfer lock may be disabled by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Activity from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'route53.amazonaws.com'
    AND rawEventMsg = 'DisableDomainTransferLock')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A domain transfer lock may be disabled by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Activity from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://github.com/elastic/detection-rules/blob/c76a39796972ecde44cb1da6df47f1b6562c9770/rules/integrations/aws/persistence_route_53_domain_transfer_lock_disabled.toml
- https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.html
- https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_DisableDomainTransferLock.html

---

## AWS Route 53 Domain Transferred to Another Account

| Field | Value |
|---|---|
| **Sigma ID** | `b056de1a-6e6e-4e40-a67e-97c9808cf41b` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | Elastic, Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_route_53_domain_transferred_to_another_account.yml)**

> Detects when a request has been made to transfer a Route 53 domain to another AWS account.

```sql
-- ============================================================
-- Title:        AWS Route 53 Domain Transferred to Another Account
-- Sigma ID:     b056de1a-6e6e-4e40-a67e-97c9808cf41b
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       Elastic, Austin Songer @austinsonger
-- Date:         2021-07-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_route_53_domain_transferred_to_another_account.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    A domain may be transferred to another AWS account by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Domain transfers from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'route53.amazonaws.com'
    AND rawEventMsg = 'TransferDomainToAnotherAwsAccount')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A domain may be transferred to another AWS account by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Domain transfers from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://github.com/elastic/detection-rules/blob/c76a39796972ecde44cb1da6df47f1b6562c9770/rules/integrations/aws/persistence_route_53_domain_transferred_to_another_account.toml

---

## AWS S3 Data Management Tampering

| Field | Value |
|---|---|
| **Sigma ID** | `78b3756a-7804-4ef7-8555-7b9024a02e2d` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1537 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_s3_data_management_tampering.yml)**

> Detects when a user tampers with S3 data management in Amazon Web Services.

```sql
-- ============================================================
-- Title:        AWS S3 Data Management Tampering
-- Sigma ID:     78b3756a-7804-4ef7-8555-7b9024a02e2d
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        exfiltration | T1537
-- Author:       Austin Songer @austinsonger
-- Date:         2021-07-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_s3_data_management_tampering.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    A S3 configuration change may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. S3 configuration change from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 's3.amazonaws.com'
    AND rawEventMsg IN ('PutBucketLogging', 'PutBucketWebsite', 'PutEncryptionConfiguration', 'PutLifecycleConfiguration', 'PutReplicationConfiguration', 'ReplicateObject', 'RestoreObject'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** A S3 configuration change may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. S3 configuration change from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://github.com/elastic/detection-rules/pull/1145/files
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_Operations.html
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLogging.html
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketWebsite.html
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketEncryption.html
- https://docs.aws.amazon.com/AmazonS3/latest/userguide/setting-repl-config-perm-overview.html
- https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html

---

## AWS SecurityHub Findings Evasion

| Field | Value |
|---|---|
| **Sigma ID** | `a607e1fe-74bf-4440-a3ec-b059b9103157` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Techniques** | T1562 |
| **Author** | Sittikorn S |
| **Status** | stable |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_securityhub_finding_evasion.yml)**

> Detects the modification of the findings on SecurityHub.

```sql
-- ============================================================
-- Title:        AWS SecurityHub Findings Evasion
-- Sigma ID:     a607e1fe-74bf-4440-a3ec-b059b9103157
-- Level:        high  |  FSM Severity: 7
-- Status:       stable
-- MITRE:        T1562
-- Author:       Sittikorn S
-- Date:         2021-06-28
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_securityhub_finding_evasion.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    System or Network administrator behaviors; DEV, UAT, SAT environment. You should apply this rule with PROD environment only.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'securityhub.amazonaws.com'
    AND rawEventMsg IN ('BatchUpdateFindings', 'DeleteInsight', 'UpdateFindings', 'UpdateInsight'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** System or Network administrator behaviors; DEV, UAT, SAT environment. You should apply this rule with PROD environment only.

**References:**
- https://docs.aws.amazon.com/cli/latest/reference/securityhub/

---

## AWS Snapshot Backup Exfiltration

| Field | Value |
|---|---|
| **Sigma ID** | `abae8fec-57bd-4f87-aff6-6e3db989843d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | exfiltration |
| **MITRE Techniques** | T1537 |
| **Author** | Darin Smith |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml)**

> Detects the modification of an EC2 snapshot's permissions to enable access from another account

```sql
-- ============================================================
-- Title:        AWS Snapshot Backup Exfiltration
-- Sigma ID:     abae8fec-57bd-4f87-aff6-6e3db989843d
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        exfiltration | T1537
-- Author:       Darin Smith
-- Date:         2021-05-17
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_snapshot_backup_exfiltration.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Valid change to a snapshot's permissions
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'ec2.amazonaws.com'
    AND rawEventMsg = 'ModifySnapshotAttribute')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Valid change to a snapshot's permissions

**References:**
- https://www.justice.gov/file/1080281/download

---

## AWS Identity Center Identity Provider Change

| Field | Value |
|---|---|
| **Sigma ID** | `d3adb3ef-b7e7-4003-9092-1924c797db35` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1556 |
| **Author** | Michael McIntyre @wtfender |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_sso_idp_change.yml)**

> Detects a change in the AWS Identity Center (FKA AWS SSO) identity provider.
A change in identity provider allows an attacker to establish persistent access or escalate privileges via user impersonation.


```sql
-- ============================================================
-- Title:        AWS Identity Center Identity Provider Change
-- Sigma ID:     d3adb3ef-b7e7-4003-9092-1924c797db35
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1556
-- Author:       Michael McIntyre @wtfender
-- Date:         2023-09-27
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_sso_idp_change.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Authorized changes to the AWS account's identity provider
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg IN ('sso-directory.amazonaws.com', 'sso.amazonaws.com')
    AND rawEventMsg IN ('AssociateDirectory', 'DisableExternalIdPConfigurationForDirectory', 'DisassociateDirectory', 'EnableExternalIdPConfigurationForDirectory'))
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Authorized changes to the AWS account's identity provider

**References:**
- https://docs.aws.amazon.com/singlesignon/latest/userguide/app-enablement.html
- https://docs.aws.amazon.com/singlesignon/latest/userguide/sso-info-in-cloudtrail.html
- https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiamidentitycentersuccessortoawssinglesign-on.html

---

## AWS STS AssumeRole Misuse

| Field | Value |
|---|---|
| **Sigma ID** | `905d389b-b853-46d0-9d3d-dea0d3a3cd49` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1548, T1550, T1550.001 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_sts_assumerole_misuse.yml)**

> Identifies the suspicious use of AssumeRole. Attackers could move laterally and escalate privileges.

```sql
-- ============================================================
-- Title:        AWS STS AssumeRole Misuse
-- Sigma ID:     905d389b-b853-46d0-9d3d-dea0d3a3cd49
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1548, T1550, T1550.001
-- Author:       Austin Songer @austinsonger
-- Date:         2021-07-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_sts_assumerole_misuse.yml
-- Unmapped:     userIdentity.type, userIdentity.sessionContext.sessionIssuer.type
-- False Pos:    AssumeRole may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; AssumeRole from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.; Automated processes that uses Terraform may lead to false positives.
-- ============================================================
-- UNMAPPED_FIELD: userIdentity.type
-- UNMAPPED_FIELD: userIdentity.sessionContext.sessionIssuer.type

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'AssumedRole'
    AND rawEventMsg = 'Role')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** AssumeRole may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; AssumeRole from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.; Automated processes that uses Terraform may lead to false positives.

**References:**
- https://github.com/elastic/detection-rules/pull/1214
- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html

---

## AWS STS GetCallerIdentity Enumeration Via TruffleHog

| Field | Value |
|---|---|
| **Sigma ID** | `9b1b8e9b-0a5d-4af1-9d2f-4c4b6e7c2c9d` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | discovery |
| **MITRE Techniques** | T1087.004 |
| **Author** | Adan Alvarez @adanalvarez |
| **Status** | experimental |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_sts_getcalleridentity_trufflehog.yml)**

> Detects the use of TruffleHog for AWS credential validation by identifying GetCallerIdentity API calls where the userAgent indicates TruffleHog.
Threat actors leverage TruffleHog to enumerate and validate exposed AWS keys.
Successful exploitation allows threat actors to confirm the validity of compromised AWS credentials, facilitating further unauthorized access and actions within the AWS environment.


```sql
-- ============================================================
-- Title:        AWS STS GetCallerIdentity Enumeration Via TruffleHog
-- Sigma ID:     9b1b8e9b-0a5d-4af1-9d2f-4c4b6e7c2c9d
-- Level:        medium  |  FSM Severity: 5
-- Status:       experimental
-- MITRE:        discovery | T1087.004
-- Author:       Adan Alvarez @adanalvarez
-- Date:         2025-10-12
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_sts_getcalleridentity_trufflehog.yml
-- Unmapped:     eventSource, eventName, userAgent
-- False Pos:    Legitimate internal security scanning or key validation that intentionally uses TruffleHog. Authorize and filter known scanner roles, IP ranges, or assumed roles as needed.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: userAgent

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'sts.amazonaws.com'
    AND rawEventMsg = 'GetCallerIdentity'
    AND rawEventMsg LIKE '%TruffleHog%')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate internal security scanning or key validation that intentionally uses TruffleHog. Authorize and filter known scanner roles, IP ranges, or assumed roles as needed.

**References:**
- https://www.rapid7.com/blog/post/tr-crimson-collective-a-new-threat-group-observed-operating-in-the-cloud/
- https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
- https://github.com/trufflesecurity/trufflehog

---

## AWS STS GetSessionToken Misuse

| Field | Value |
|---|---|
| **Sigma ID** | `b45ab1d2-712f-4f01-a751-df3826969807` |
| **Level** | low |
| **FSM Severity** | 3 |
| **MITRE Techniques** | T1548, T1550, T1550.001 |
| **Author** | Austin Songer @austinsonger |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_sts_getsessiontoken_misuse.yml)**

> Identifies the suspicious use of GetSessionToken. Tokens could be created and used by attackers to move laterally and escalate privileges.

```sql
-- ============================================================
-- Title:        AWS STS GetSessionToken Misuse
-- Sigma ID:     b45ab1d2-712f-4f01-a751-df3826969807
-- Level:        low  |  FSM Severity: 3
-- Status:       test
-- MITRE:        T1548, T1550, T1550.001
-- Author:       Austin Songer @austinsonger
-- Date:         2021-07-24
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_sts_getsessiontoken_misuse.yml
-- Unmapped:     eventSource, eventName, userIdentity.type
-- False Pos:    GetSessionToken may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. GetSessionToken from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName
-- UNMAPPED_FIELD: userIdentity.type

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'sts.amazonaws.com'
    AND rawEventMsg = 'GetSessionToken'
    AND rawEventMsg = 'IAMUser')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** GetSessionToken may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. GetSessionToken from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://github.com/elastic/detection-rules/pull/1213
- https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html

---

## AWS Suspicious SAML Activity

| Field | Value |
|---|---|
| **Sigma ID** | `f43f5d2f-3f2a-4cc8-b1af-81fde7dbaf0e` |
| **Level** | medium |
| **FSM Severity** | 5 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1078, T1548, T1550, T1550.001 |
| **Author** | Austin Songer |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_susp_saml_activity.yml)**

> Identifies when suspicious SAML activity has occurred in AWS. An adversary could gain backdoor access via SAML.

```sql
-- ============================================================
-- Title:        AWS Suspicious SAML Activity
-- Sigma ID:     f43f5d2f-3f2a-4cc8-b1af-81fde7dbaf0e
-- Level:        medium  |  FSM Severity: 5
-- Status:       test
-- MITRE:        persistence | T1078, T1548, T1550, T1550.001
-- Author:       Austin Songer
-- Date:         2021-09-22
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_susp_saml_activity.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Automated processes that uses Terraform may lead to false positives.; SAML Provider could be updated by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; SAML Provider being updated from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'iam.amazonaws.com'
    AND rawEventMsg = 'UpdateSAMLProvider')
  OR (rawEventMsg = 'sts.amazonaws.com'
    AND rawEventMsg = 'AssumeRoleWithSAML')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Automated processes that uses Terraform may lead to false positives.; SAML Provider could be updated by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.; SAML Provider being updated from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

**References:**
- https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateSAMLProvider.html
- https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html

---

## AWS User Login Profile Was Modified

| Field | Value |
|---|---|
| **Sigma ID** | `055fb148-60f8-462d-ad16-26926ce050f1` |
| **Level** | high |
| **FSM Severity** | 7 |
| **MITRE Tactics** | persistence |
| **MITRE Techniques** | T1098 |
| **Author** | toffeebr33k |
| **Status** | test |

**[View on GitHub ↗](https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_update_login_profile.yml)**

> Detects activity when someone is changing passwords on behalf of other users.
An attacker with the "iam:UpdateLoginProfile" permission on other users can change the password used to login to the AWS console on any user that already has a login profile setup.


```sql
-- ============================================================
-- Title:        AWS User Login Profile Was Modified
-- Sigma ID:     055fb148-60f8-462d-ad16-26926ce050f1
-- Level:        high  |  FSM Severity: 7
-- Status:       test
-- MITRE:        persistence | T1098
-- Author:       toffeebr33k
-- Date:         2021-08-09
-- GitHub:       https://github.com/SigmaHQ/sigma/blob/main/rules/cloud/aws/cloudtrail/aws_update_login_profile.yml
-- Unmapped:     eventSource, eventName
-- False Pos:    Legitimate user account administration
-- ============================================================
-- UNMAPPED_FIELD: eventSource
-- UNMAPPED_FIELD: eventName

SELECT
  phRecvTime,
  reptDevName,
  reptDevIpAddrV4,
  user,
  rawEventMsg
FROM fsiem.events
WHERE eventType IN ('AWS-CloudTrail-*')
  AND phRecvTime >= now() - INTERVAL 24 HOUR
  AND (rawEventMsg = 'iam.amazonaws.com'
    AND rawEventMsg = 'UpdateLoginProfile')
ORDER BY phRecvTime DESC
LIMIT 1000;
```

**False Positives:** Legitimate user account administration

**References:**
- https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation

---
