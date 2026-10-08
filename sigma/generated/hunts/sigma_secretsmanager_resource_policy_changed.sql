-- title: Sigma: Secrets Manager Resource Policy Changed
-- attack: T1098 / T1555.006
-- purpose: A resource policy on a secret was put or deleted, which can grant another principal or account read access to it. (Sigma rule 6d0f5b4e-9a8f-4a52-8f3c-2b6f0c1d7e07, level medium, status experimental)
-- requires: cloudtrail
-- schedule-time-column: ts
-- schedule-baseline: false
-- generated-from: sigma/rules/aws/secretsmanager_resource_policy_changed.yml. Do not edit: change the rule and run scripts/sigma_convert.py.
-- falsepositives: Infrastructure-as-code deployments managing secret policies
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  eventsource, eventname, errorcode, awsregion, sourceipaddress, useragent,
  coalesce(useridentity.arn, useridentity.principalid) AS identity,
  requestparameters
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND (((eventsource IS NOT NULL AND lower(eventsource) = 'secretsmanager.amazonaws.com') AND ((eventname IS NOT NULL AND lower(eventname) = 'putresourcepolicy') OR (eventname IS NOT NULL AND lower(eventname) = 'deleteresourcepolicy'))) AND (NOT (errorcode IS NOT NULL AND lower(errorcode) LIKE '%' ESCAPE '!')))
ORDER BY ts DESC
LIMIT 500
