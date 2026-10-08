-- title: Console password guessing followed by a successful sign-in
-- attack: T1110 Brute Force (T1110.003 Password Spraying when many identities are tried)
-- purpose: Source IPs with 5+ failed console sign-ins and a later success in the same hour, listing every identity they tried.
-- Grouped by source IP rather than user: failed sign-ins for unknown users carry no usable identity, and spraying spreads across users.
WITH attempts AS (
  SELECT
    sourceipaddress,
    from_iso8601_timestamp(eventtime) AS ts,
    date_trunc('hour', from_iso8601_timestamp(eventtime)) AS hour,
    coalesce(useridentity.username, useridentity.arn, 'unknown') AS identity,
    json_extract_scalar(responseelements, '$.ConsoleLogin') AS outcome
  FROM "${database}"."${table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND eventname = 'ConsoleLogin'
)
SELECT
  sourceipaddress,
  hour,
  count_if(outcome = 'Failure') AS failures,
  count_if(outcome = 'Success') AS successes,
  count(DISTINCT identity) AS identities_tried,
  array_agg(DISTINCT identity) AS identities,
  min(CASE WHEN outcome = 'Failure' THEN ts END) AS first_failure,
  max(CASE WHEN outcome = 'Success' THEN ts END) AS last_success
FROM attempts
GROUP BY sourceipaddress, hour
HAVING count_if(outcome = 'Failure') >= 5
   AND max(CASE WHEN outcome = 'Success' THEN ts END) > min(CASE WHEN outcome = 'Failure' THEN ts END)
ORDER BY failures DESC
LIMIT 500
