-- title: Sigma: SSM Command or Session Started by a Person
-- attack: T1651
-- purpose: Systems Manager ran a command or opened a session on instances on behalf of a human principal rather than an AWS service, which is how an attacker with console or API access gets a shell. (Sigma rule 6d0f5b4e-9a8f-4a52-8f3c-2b6f0c1d7e06, level medium, status experimental)
-- requires: cloudtrail
-- schedule-time-column: ts
-- schedule-baseline: false
-- generated-from: sigma/rules/aws/ssm_command_by_human.yml. Do not edit: change the rule and run scripts/sigma_convert.py.
-- falsepositives: Administrators using Session Manager instead of SSH (the point is to make it attributable)
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  eventsource, eventname, errorcode, awsregion, sourceipaddress, useragent,
  coalesce(useridentity.arn, useridentity.principalid) AS identity,
  requestparameters
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND (((eventsource IS NOT NULL AND lower(eventsource) = 'ssm.amazonaws.com') AND ((eventname IS NOT NULL AND lower(eventname) = 'sendcommand') OR (eventname IS NOT NULL AND lower(eventname) = 'startsession'))) AND (NOT (useridentity.invokedby IS NOT NULL AND lower(useridentity.invokedby) LIKE '%.amazonaws.com' ESCAPE '!')))
ORDER BY ts DESC
LIMIT 500
