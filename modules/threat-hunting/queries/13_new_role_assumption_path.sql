-- title: Role assumption by a caller that has never assumed that role
-- attack: T1078.004 Valid Accounts: Cloud Accounts / T1550.001 Use Alternate Authentication Material: Application Access Token
-- purpose: AssumeRole calls in the recent window whose caller-to-role pair is absent from the baseline window, flagging cross-account hops. This is how lateral movement between roles and accounts looks.
WITH assumptions AS (
  SELECT
    from_iso8601_timestamp(eventtime) AS ts,
    coalesce(useridentity.sessioncontext.sessionissuer.arn, useridentity.arn, useridentity.principalid) AS caller,
    useridentity.accountid AS caller_account,
    json_extract_scalar(requestparameters, '$.roleArn') AS role_arn,
    json_extract_scalar(requestparameters, '$.roleSessionName') AS session_name,
    sourceipaddress,
    errorcode
  FROM "${database}"."${table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND eventsource = 'sts.amazonaws.com'
    AND eventname = 'AssumeRole'
    AND useridentity.type <> 'AWSService'
    AND useridentity.invokedby IS NULL
),
baseline AS (
  SELECT DISTINCT caller, role_arn
  FROM assumptions
  WHERE ts < current_timestamp - interval '${recent_days}' day
    AND errorcode IS NULL
)
SELECT
  a.caller,
  a.role_arn,
  split_part(a.role_arn, ':', 5) <> a.caller_account AS cross_account,
  count(*) AS attempts,
  count_if(a.errorcode IS NOT NULL) AS denied,
  array_agg(DISTINCT a.session_name) AS session_names,
  array_agg(DISTINCT a.sourceipaddress) AS source_ips,
  min(a.ts) AS first_seen
FROM assumptions a
LEFT JOIN baseline b ON a.caller = b.caller AND a.role_arn = b.role_arn
WHERE a.ts >= current_timestamp - interval '${recent_days}' day
  AND b.caller IS NULL
GROUP BY a.caller, a.role_arn, a.caller_account
ORDER BY cross_account DESC, first_seen DESC
LIMIT 500
