-- title: Every action taken as the root user
-- attack: T1078.004 Valid Accounts: Cloud Accounts
-- purpose: Root activity with MFA status and source, excluding actions AWS services perform on root's behalf. Root should almost never act interactively.
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  eventsource,
  eventname,
  errorcode,
  sourceipaddress,
  useragent,
  coalesce(
    json_extract_scalar(additionaleventdata, '$.MFAUsed'),
    useridentity.sessioncontext.attributes.mfaauthenticated
  ) AS mfa,
  awsregion
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND useridentity.type = 'Root'
  AND useridentity.invokedby IS NULL
  AND eventtype <> 'AwsServiceEvent'
ORDER BY ts DESC
LIMIT 500
