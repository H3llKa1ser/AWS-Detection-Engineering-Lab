-- title: Rapid enumeration across many services
-- attack: T1580 Cloud Infrastructure Discovery / T1526 Cloud Service Discovery / T1087.004 Account Discovery: Cloud Account
-- purpose: Identities that made 30+ distinct List/Describe/Get calls across 5+ services in one hour, the footprint of Pacu, ScoutSuite or an attacker orienting.
-- schedule-time-column: hour
-- schedule-baseline: false
-- AWS services acting for you (Config, Security Hub, the console's own lookups) report a *.amazonaws.com source and are excluded. CSPM tools you run will still appear: allow-list them by identity.
SELECT
  useridentity.arn AS identity,
  useridentity.type AS identity_type,
  date_trunc('hour', from_iso8601_timestamp(eventtime)) AS hour,
  count(DISTINCT eventname) AS distinct_apis,
  count(DISTINCT eventsource) AS distinct_services,
  count(*) AS calls,
  array_agg(DISTINCT sourceipaddress) AS source_ips,
  array_agg(DISTINCT useragent) AS user_agents
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND regexp_like(eventname, '^(List|Describe|Get)')
  AND useridentity.type IN ('IAMUser', 'AssumedRole', 'Root', 'FederatedUser')
  AND sourceipaddress NOT LIKE '%.amazonaws.com'
  AND useridentity.invokedby IS NULL
GROUP BY 1, 2, 3
HAVING count(DISTINCT eventname) >= 30
   AND count(DISTINCT eventsource) >= 5
ORDER BY distinct_apis DESC
LIMIT 500
