-- title: Sigma: GuardDuty Detector Deleted or Disabled
-- attack: T1562.001
-- purpose: A GuardDuty detector was deleted, or updated with enable set to false, removing managed threat detection from the region. (Sigma rule 6d0f5b4e-9a8f-4a52-8f3c-2b6f0c1d7e01, level high, status experimental)
-- requires: cloudtrail
-- schedule-time-column: ts
-- schedule-baseline: false
-- generated-from: sigma/rules/aws/guardduty_detector_disabled.yml. Do not edit: change the rule and run scripts/sigma_convert.py.
-- falsepositives: Decommissioning a region or account
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  eventsource, eventname, errorcode, awsregion, sourceipaddress, useragent,
  coalesce(useridentity.arn, useridentity.principalid) AS identity,
  requestparameters
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND (((eventsource IS NOT NULL AND lower(eventsource) = 'guardduty.amazonaws.com') AND (eventname IS NOT NULL AND lower(eventname) = 'deletedetector')) OR ((eventsource IS NOT NULL AND lower(eventsource) = 'guardduty.amazonaws.com') AND (eventname IS NOT NULL AND lower(eventname) = 'updatedetector') AND (json_extract_scalar(requestparameters, '$.enable') IS NOT NULL AND lower(json_extract_scalar(requestparameters, '$.enable')) = 'false')))
ORDER BY ts DESC
LIMIT 500
