-- title: AWS API calls from threat-intel IPs and ranges
-- attack: T1078.004 Valid Accounts: Cloud Accounts / TA0001 Initial Access
-- purpose: API calls and console sign-ins whose source IP matches an active IP or CIDR indicator: credentials being used from known attacker infrastructure.
-- requires: cloudtrail,intel
-- schedule-time-column: last_seen
-- schedule-baseline: false
-- Calls made by AWS services on your behalf report a service name, not an IP, and are skipped. A match here means valid credentials in hostile hands: rotate first, investigate second.
WITH ${intel_active},
calls AS (
  SELECT
    coalesce(useridentity.arn, useridentity.principalid) AS identity,
    useridentity.accesskeyid AS access_key,
    eventname, errorcode, sourceipaddress,
    from_iso8601_timestamp(eventtime) AS ts,
    (TRY_CAST(split_part(sourceipaddress, '.', 1) AS bigint) * 16777216 + TRY_CAST(split_part(sourceipaddress, '.', 2) AS bigint) * 65536 + TRY_CAST(split_part(sourceipaddress, '.', 3) AS bigint) * 256 + TRY_CAST(split_part(sourceipaddress, '.', 4) AS bigint)) AS ip_int
  FROM "${database}"."${table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND regexp_like(sourceipaddress, '^[0-9]{1,3}([.][0-9]{1,3}){3}$')
)
SELECT
  c.identity,
  c.access_key,
  c.sourceipaddress,
  i.indicator, i.source, i.confidence, i.description,
  count(*) AS calls,
  count_if(c.errorcode IS NULL) AS succeeded,
  array_agg(DISTINCT c.eventname) AS apis,
  min(c.ts) AS first_seen,
  max(c.ts) AS last_seen
FROM calls c
JOIN intel i ON i.kind = 'ip' AND c.ip_int BETWEEN i.lo AND i.hi
GROUP BY c.identity, c.access_key, c.sourceipaddress, i.indicator, i.source, i.confidence, i.description, i.confidence_rank
ORDER BY i.confidence_rank DESC, succeeded DESC
LIMIT 500
