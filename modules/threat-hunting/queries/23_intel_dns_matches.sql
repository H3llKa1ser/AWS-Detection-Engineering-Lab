-- title: DNS lookups of threat-intel domains, or answers pointing at threat-intel IPs
-- attack: TA0011 Command and Control / T1071.004 Application Layer Protocol: DNS
-- purpose: Queries for an active domain indicator or any of its subdomains, and queries whose answers resolve to an active IP or CIDR indicator, with whether DNS Firewall already acted.
-- requires: dns,intel
-- schedule-time-column: last_seen
-- schedule-baseline: false
-- Subdomain match uses a dot boundary: evil.com matches a.evil.com, never notevil.com.
WITH ${intel_active},
q AS (
  SELECT
    srcids.instance AS instance,
    regexp_replace(lower(query_name), '[.]$', '') AS name,
    firewall_rule_action,
    transform(answers, a -> a.rdata) AS ips,
    from_iso8601_timestamp(query_timestamp) AS ts
  FROM "${database}"."${dns_table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
),
by_name AS (
  SELECT q.instance, q.name, 'domain' AS matched_on, i.indicator, i.source, i.confidence, i.confidence_rank,
         i.description, q.firewall_rule_action, q.ts
  FROM q
  JOIN intel i
    ON i.kind = 'domain'
   AND (q.name = i.indicator OR strpos(reverse(q.name), reverse('.' || i.indicator)) = 1)
),
answer_ips AS (
  SELECT q.instance, q.name, q.firewall_rule_action, q.ts, ip
  FROM q
  CROSS JOIN UNNEST(q.ips) AS t (ip)
  WHERE regexp_like(ip, '^[0-9]{1,3}([.][0-9]{1,3}){3}$')
),
by_answer AS (
  SELECT a.instance, a.name, 'answer ' || a.ip AS matched_on, i.indicator, i.source, i.confidence, i.confidence_rank,
         i.description, a.firewall_rule_action, a.ts
  FROM answer_ips a
  JOIN intel i ON i.kind = 'ip' AND (TRY_CAST(split_part(a.ip, '.', 1) AS bigint) * 16777216 + TRY_CAST(split_part(a.ip, '.', 2) AS bigint) * 65536 + TRY_CAST(split_part(a.ip, '.', 3) AS bigint) * 256 + TRY_CAST(split_part(a.ip, '.', 4) AS bigint)) BETWEEN i.lo AND i.hi
),
matches AS (
  SELECT * FROM by_name
  UNION ALL
  SELECT * FROM by_answer
)
SELECT
  instance,
  name AS query_name,
  matched_on,
  indicator, source, confidence, description,
  count(*) AS lookups,
  array_agg(DISTINCT coalesce(firewall_rule_action, 'none')) AS dns_firewall,
  min(ts) AS first_seen,
  max(ts) AS last_seen
FROM matches
GROUP BY instance, name, matched_on, indicator, source, confidence, description, confidence_rank
ORDER BY confidence_rank DESC, lookups DESC
LIMIT 500
