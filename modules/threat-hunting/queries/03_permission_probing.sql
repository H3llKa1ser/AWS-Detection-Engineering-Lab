-- title: Permission probing (AccessDenied across many APIs)
-- attack: T1580 Cloud Infrastructure Discovery / T1069.003 Permission Groups Discovery: Cloud Groups
-- purpose: Identities denied on 10+ distinct APIs within one hour, the pattern of a stolen key being tested to learn what it can do.
-- schedule-time-column: hour
-- schedule-baseline: false
SELECT
  coalesce(useridentity.arn, useridentity.principalid) AS identity,
  useridentity.accesskeyid AS access_key,
  date_trunc('hour', from_iso8601_timestamp(eventtime)) AS hour,
  count(*) AS denied_calls,
  count(DISTINCT eventname) AS distinct_apis,
  count(DISTINCT eventsource) AS distinct_services,
  array_agg(DISTINCT sourceipaddress) AS source_ips,
  array_agg(DISTINCT eventname) AS apis
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND (errorcode LIKE '%AccessDenied%' OR errorcode LIKE '%UnauthorizedOperation%')
GROUP BY 1, 2, 3
HAVING count(DISTINCT eventname) >= 10
ORDER BY distinct_apis DESC
LIMIT 500
