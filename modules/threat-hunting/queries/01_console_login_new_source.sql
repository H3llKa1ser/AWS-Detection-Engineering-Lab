-- title: Console sign-in from a source IP new for that identity
-- attack: T1078.004 Valid Accounts: Cloud Accounts
-- purpose: Successful console sign-ins in the recent window from an IP the same identity never signed in from during the baseline window.
-- schedule-time-column: first_seen
-- schedule-baseline: true
-- Tuning: a brand-new identity has no baseline, so every IP it uses appears once. Expected for new staff; worth a look otherwise.
WITH logins AS (
  SELECT
    coalesce(useridentity.arn, useridentity.username) AS identity,
    sourceipaddress,
    from_iso8601_timestamp(eventtime) AS ts,
    useragent,
    json_extract_scalar(additionaleventdata, '$.MFAUsed') AS mfa_used
  FROM "${database}"."${table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND eventname = 'ConsoleLogin'
    AND json_extract_scalar(responseelements, '$.ConsoleLogin') = 'Success'
),
baseline AS (
  SELECT DISTINCT identity, sourceipaddress
  FROM logins
  WHERE ts < current_timestamp - interval '${recent_days}' day
)
SELECT
  l.identity,
  l.sourceipaddress,
  min(l.ts) AS first_seen,
  count(*) AS logins,
  array_agg(DISTINCT l.mfa_used) AS mfa_used,
  array_agg(DISTINCT l.useragent) AS user_agents
FROM logins l
LEFT JOIN baseline b
  ON l.identity = b.identity AND l.sourceipaddress = b.sourceipaddress
WHERE l.ts >= current_timestamp - interval '${recent_days}' day
  AND b.identity IS NULL
GROUP BY l.identity, l.sourceipaddress
ORDER BY first_seen DESC
LIMIT 500
