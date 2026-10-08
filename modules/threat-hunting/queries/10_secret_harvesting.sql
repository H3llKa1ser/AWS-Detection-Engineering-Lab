-- title: Secret and decrypted-parameter harvesting
-- attack: T1555.006 Credentials from Password Stores: Cloud Secrets Management Stores
-- purpose: Identities that read 5+ distinct Secrets Manager secrets or decrypted SSM parameters in one day, with how many reads were denied.
-- schedule-time-column: last_read
-- schedule-baseline: false
WITH reads AS (
  SELECT
    coalesce(useridentity.arn, useridentity.principalid) AS identity,
    from_iso8601_timestamp(eventtime) AS ts,
    date_trunc('day', from_iso8601_timestamp(eventtime)) AS day,
    coalesce(
      json_extract_scalar(requestparameters, '$.secretId'),
      json_extract_scalar(requestparameters, '$.name'),
      json_extract_scalar(requestparameters, '$.path'),
      CAST(json_extract(requestparameters, '$.names') AS varchar)
    ) AS secret,
    errorcode,
    sourceipaddress
  FROM "${database}"."${table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND sourceipaddress NOT LIKE '%.amazonaws.com'
    AND (
         (eventsource = 'secretsmanager.amazonaws.com' AND eventname IN ('GetSecretValue', 'BatchGetSecretValue'))
      OR (eventsource = 'ssm.amazonaws.com' AND eventname IN ('GetParameter', 'GetParameters', 'GetParametersByPath')
          AND json_extract_scalar(requestparameters, '$.withDecryption') = 'true')
    )
)
SELECT
  identity,
  day,
  count(DISTINCT secret) AS distinct_secrets,
  count(*) AS reads,
  count_if(errorcode IS NOT NULL) AS denied,
  max(ts) AS last_read,
  array_agg(DISTINCT sourceipaddress) AS source_ips,
  array_agg(DISTINCT secret) AS secrets
FROM reads
GROUP BY identity, day
HAVING count(DISTINCT secret) >= 5
ORDER BY distinct_secrets DESC
LIMIT 500
