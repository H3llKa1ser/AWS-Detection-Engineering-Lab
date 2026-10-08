-- title: Tampering with logging, detection and alerting (this lab's own sensors)
-- attack: T1562.008 Impair Defenses: Disable or Modify Cloud Logs / T1562.001 Impair Defenses: Disable or Modify Tools
-- purpose: Calls that stop, delete or weaken CloudTrail, GuardDuty, Security Hub, Config, flow logs, Resolver query logging, DNS Firewall, alarms or alert routing, including failed attempts.
-- schedule-time-column: ts
-- schedule-baseline: false
-- Your own Terraform applies appear here too: confirm the actor is your deployment principal and matches a change you made.
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  CASE eventsource
    WHEN 'cloudtrail.amazonaws.com' THEN 'CloudTrail'
    WHEN 'guardduty.amazonaws.com' THEN 'GuardDuty'
    WHEN 'securityhub.amazonaws.com' THEN 'Security Hub'
    WHEN 'config.amazonaws.com' THEN 'AWS Config'
    WHEN 'ec2.amazonaws.com' THEN 'VPC Flow Logs'
    WHEN 'route53resolver.amazonaws.com' THEN 'Resolver logging / DNS Firewall'
    WHEN 'logs.amazonaws.com' THEN 'CloudWatch Logs'
    WHEN 'monitoring.amazonaws.com' THEN 'CloudWatch alarms'
    WHEN 'events.amazonaws.com' THEN 'EventBridge routing'
    WHEN 'sns.amazonaws.com' THEN 'SNS alerting'
    WHEN 'kms.amazonaws.com' THEN 'KMS (log encryption key)'
  END AS sensor,
  eventname,
  errorcode,
  coalesce(useridentity.arn, useridentity.principalid) AS actor,
  sourceipaddress,
  useragent,
  requestparameters
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND (
       (eventsource = 'cloudtrail.amazonaws.com' AND eventname IN ('StopLogging', 'DeleteTrail', 'UpdateTrail', 'PutEventSelectors', 'PutInsightSelectors'))
    OR (eventsource = 'guardduty.amazonaws.com' AND eventname IN ('DeleteDetector', 'UpdateDetector', 'UpdateDetectorFeature', 'DisassociateFromMasterAccount', 'DisassociateFromAdministratorAccount', 'CreateIPSet', 'UpdateIPSet', 'CreateFilter', 'UpdateFilter'))
    OR (eventsource = 'securityhub.amazonaws.com' AND eventname IN ('DisableSecurityHub', 'BatchDisableStandards', 'UpdateStandardsControl', 'BatchUpdateFindings'))
    OR (eventsource = 'config.amazonaws.com' AND eventname IN ('StopConfigurationRecorder', 'DeleteConfigurationRecorder', 'DeleteDeliveryChannel', 'DeleteConfigRule'))
    OR (eventsource = 'ec2.amazonaws.com' AND eventname = 'DeleteFlowLogs')
    OR (eventsource = 'route53resolver.amazonaws.com' AND eventname IN ('DeleteResolverQueryLogConfig', 'DisassociateResolverQueryLogConfig', 'DisassociateFirewallRuleGroup', 'UpdateFirewallConfig', 'UpdateFirewallRule', 'DeleteFirewallRule', 'UpdateFirewallDomains', 'UpdateFirewallRuleGroupAssociation'))
    OR (eventsource = 'logs.amazonaws.com' AND eventname IN ('DeleteLogGroup', 'DeleteLogStream', 'DeleteMetricFilter', 'PutRetentionPolicy', 'DeleteResourcePolicy'))
    OR (eventsource = 'monitoring.amazonaws.com' AND eventname IN ('DeleteAlarms', 'DisableAlarmActions'))
    OR (eventsource = 'events.amazonaws.com' AND eventname IN ('DisableRule', 'DeleteRule', 'RemoveTargets'))
    OR (eventsource = 'sns.amazonaws.com' AND eventname IN ('DeleteTopic', 'Unsubscribe', 'SetTopicAttributes'))
    OR (eventsource = 'kms.amazonaws.com' AND eventname IN ('DisableKey', 'ScheduleKeyDeletion', 'PutKeyPolicy'))
  )
ORDER BY ts DESC
LIMIT 500
