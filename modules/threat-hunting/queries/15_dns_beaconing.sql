-- title: DNS beaconing (one name resolved at machine-regular intervals)
-- attack: T1071.004 Application Layer Protocol: DNS / T1029 Scheduled Transfer
-- purpose: Instance and domain pairs with 12+ lookups whose gaps are nearly constant (low jitter): the rhythm of implant check-ins, not people or normal apps.
-- requires: dns
-- schedule-time-column: last_seen
-- schedule-baseline: false
-- Lookups less than 2 seconds apart are collapsed first: implants often ask for A and AAAA together, and those zero gaps would otherwise hide a perfect rhythm.
-- AWS API endpoints (SSM agent, SDK credential refresh) and EC2-internal names (service discovery) poll on timers by design and are excluded.
-- Tuning: other agents polling on timers (update checks, telemetry) also beacon. Add their domains to the exclusion regex once reviewed.
WITH lookups AS (
  SELECT
    srcids.instance AS instance,
    regexp_replace(lower(query_name), '[.]$', '') AS domain,
    from_iso8601_timestamp(query_timestamp) AS ts
  FROM "${database}"."${dns_table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND srcids.instance IS NOT NULL
    AND NOT regexp_like(lower(query_name), '([.]amazonaws[.]com|[.]internal)[.]?$')  -- AWS API endpoints, EC2-internal names
),
gaps AS (
  SELECT instance, domain, ts,
    to_unixtime(ts) - to_unixtime(lag(ts) OVER (PARTITION BY instance, domain ORDER BY ts)) AS gap_seconds
  FROM lookups
)
SELECT
  instance,
  domain,
  count(*) AS lookups,
  round(avg(gap_seconds)) AS avg_interval_seconds,
  round(stddev(gap_seconds) / avg(gap_seconds), 3) AS jitter,
  min(ts) AS first_seen,
  max(ts) AS last_seen
FROM gaps
WHERE gap_seconds >= 2
GROUP BY instance, domain
HAVING count(*) >= 11
   AND avg(gap_seconds) BETWEEN 10 AND 21600
   AND stddev(gap_seconds) / avg(gap_seconds) < 0.1
ORDER BY jitter
LIMIT 500
