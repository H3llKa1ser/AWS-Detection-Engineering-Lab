-- title: Sigma: Account Left Its AWS Organization
-- attack: T1666
-- purpose: An account left its organization, escaping service control policies, organization CloudTrail and central security tooling. (Sigma rule 6d0f5b4e-9a8f-4a52-8f3c-2b6f0c1d7e08, level critical, status experimental)
-- requires: cloudtrail
-- schedule-time-column: ts
-- schedule-baseline: false
-- generated-from: sigma/rules/aws/organizations_leave.yml. Do not edit: change the rule and run scripts/sigma_convert.py.
-- falsepositives: Planned account divestment
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  eventsource, eventname, errorcode, awsregion, sourceipaddress, useragent,
  coalesce(useridentity.arn, useridentity.principalid) AS identity,
  requestparameters
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND ((eventsource IS NOT NULL AND lower(eventsource) = 'organizations.amazonaws.com') AND (eventname IS NOT NULL AND lower(eventname) = 'leaveorganization'))
ORDER BY ts DESC
LIMIT 500
