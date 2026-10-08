-- title: Write activity in a region this account does not normally use
-- attack: T1535 Unused/Unsupported Cloud Regions
-- purpose: Mutating API calls in the recent window in regions that had no mutating calls in the baseline window, where attackers hide miners and persistence.
-- schedule-time-column: first_seen
-- schedule-baseline: true
-- Global-service events (IAM, STS, sign-in) are excluded because they are recorded in us-east-1 regardless of where they came from.
WITH writes AS (
  SELECT
    awsregion,
    from_iso8601_timestamp(eventtime) AS ts,
    coalesce(useridentity.arn, useridentity.principalid) AS identity,
    eventname,
    sourceipaddress
  FROM "${database}"."${table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND readonly = 'false'
    AND sourceipaddress NOT LIKE '%.amazonaws.com'
    AND eventsource NOT IN ('iam.amazonaws.com', 'sts.amazonaws.com', 'signin.amazonaws.com')
),
baseline AS (
  SELECT DISTINCT awsregion
  FROM writes
  WHERE ts < current_timestamp - interval '${recent_days}' day
)
SELECT
  w.awsregion,
  count(*) AS write_calls,
  count(DISTINCT w.identity) AS identities,
  array_agg(DISTINCT w.identity) AS who,
  array_agg(DISTINCT w.eventname) AS what,
  array_agg(DISTINCT w.sourceipaddress) AS source_ips,
  min(w.ts) AS first_seen,
  max(w.ts) AS last_seen
FROM writes w
LEFT JOIN baseline b ON w.awsregion = b.awsregion
WHERE w.ts >= current_timestamp - interval '${recent_days}' day
  AND b.awsregion IS NULL
GROUP BY w.awsregion
ORDER BY write_calls DESC
