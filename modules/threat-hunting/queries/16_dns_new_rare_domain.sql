-- title: Newly seen, rare domains (one instance, never seen before)
-- attack: T1568 Dynamic Resolution / T1071.004 Application Layer Protocol: DNS
-- purpose: Domains first resolved in the recent window and by only one instance across the whole lookback. Attacker infrastructure is new and narrow; SaaS is old and wide.
-- requires: dns
-- schedule-time-column: first_seen
-- schedule-baseline: true
-- The domain is approximated as the last two labels, so multi-part suffixes (example.co.uk) group a little too broadly.
WITH named AS (
  SELECT
    srcids.instance AS instance,
    split(regexp_replace(lower(query_name), '[.]$', ''), '.') AS labels,
    lower(query_name) AS query_name,
    from_iso8601_timestamp(query_timestamp) AS ts
  FROM "${database}"."${dns_table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND srcids.instance IS NOT NULL
    AND NOT regexp_like(lower(query_name), '([.]amazonaws[.]com|[.]internal|[.]arpa)[.]?$')
)
SELECT
  element_at(labels, -2) || '.' || element_at(labels, -1) AS domain,
  min(ts) AS first_seen,
  count(*) AS lookups,
  max(instance) AS instance,
  array_agg(DISTINCT query_name) AS names
FROM named
WHERE cardinality(labels) >= 2
GROUP BY 1
HAVING min(ts) >= current_timestamp - interval '${recent_days}' day
   AND count(DISTINCT instance) = 1
ORDER BY first_seen DESC
LIMIT 500
