-- title: Sigma: Access Key Created for the Root User
-- attack: T1098.001
-- purpose: The root user created an access key. Root access keys are almost never legitimate and give unrestricted, hard-to-scope programmatic access. (Sigma rule 6d0f5b4e-9a8f-4a52-8f3c-2b6f0c1d7e03, level critical, status experimental)
-- requires: cloudtrail
-- schedule-time-column: ts
-- schedule-baseline: false
-- generated-from: sigma/rules/aws/iam_root_access_key_created.yml. Do not edit: change the rule and run scripts/sigma_convert.py.
-- falsepositives: None expected
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  eventsource, eventname, errorcode, awsregion, sourceipaddress, useragent,
  coalesce(useridentity.arn, useridentity.principalid) AS identity,
  requestparameters
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND ((eventsource IS NOT NULL AND lower(eventsource) = 'iam.amazonaws.com') AND (eventname IS NOT NULL AND lower(eventname) = 'createaccesskey') AND (useridentity.type IS NOT NULL AND lower(useridentity.type) = 'root'))
ORDER BY ts DESC
LIMIT 500
