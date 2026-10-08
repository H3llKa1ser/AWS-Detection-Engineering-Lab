-- title: Sigma: EC2 Instance User Data Modified
-- attack: T1037
-- purpose: An instance's user data was changed. User data runs as root at boot, so changing it is a quiet way to plant code that runs on the next restart. (Sigma rule 6d0f5b4e-9a8f-4a52-8f3c-2b6f0c1d7e04, level medium, status experimental)
-- requires: cloudtrail
-- schedule-time-column: ts
-- schedule-baseline: false
-- generated-from: sigma/rules/aws/ec2_user_data_modified.yml. Do not edit: change the rule and run scripts/sigma_convert.py.
-- falsepositives: Configuration management that rewrites user data (should be rare and attributable)
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  eventsource, eventname, errorcode, awsregion, sourceipaddress, useragent,
  coalesce(useridentity.arn, useridentity.principalid) AS identity,
  requestparameters
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND ((eventsource IS NOT NULL AND lower(eventsource) = 'ec2.amazonaws.com') AND (eventname IS NOT NULL AND lower(eventname) = 'modifyinstanceattribute') AND (json_extract_scalar(requestparameters, '$.userData') IS NOT NULL AND lower(json_extract_scalar(requestparameters, '$.userData')) LIKE '%' ESCAPE '!'))
ORDER BY ts DESC
LIMIT 500
