-- title: Egress to public IPs the instance never resolved through DNS
-- attack: TA0011 Command and Control (hard-coded infrastructure) / T1071 Application Layer Protocol
-- purpose: Accepted connections from an instance to public IPs that no DNS answer to that instance returned in the prior 24 hours. Malware with hard-coded IPs skips DNS; most software does not.
-- requires: flow,dns
-- schedule-time-column: first_seen
-- schedule-baseline: false
-- Joins flow logs to Resolver query logs from the same VPCs. An instance using its own resolver instead of the Route 53 Resolver will appear here too, which is worth knowing.
WITH egress AS (
  SELECT instance_id, dstaddr, dstport, bytes, from_unixtime(start) AS ts
  FROM "${database}"."${flow_table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND action = 'ACCEPT'
    AND flow_direction = 'egress'
    AND coalesce(instance_id, '-') <> '-'
    AND coalesce(pkt_dst_aws_service, '-') = '-'
    AND NOT regexp_like(dstaddr, '^(10[.]|172[.](1[6-9]|2[0-9]|3[01])[.]|192[.]168[.]|169[.]254[.]|127[.]|100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.])')
),
resolved AS (
  SELECT
    srcids.instance AS instance,
    from_iso8601_timestamp(query_timestamp) AS ts,
    transform(answers, a -> a.rdata) AS ips
  FROM "${database}"."${dns_table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day - interval '1' day, '%Y/%m/%d')
    AND cardinality(answers) > 0
)
SELECT
  e.instance_id,
  e.dstaddr,
  array_agg(DISTINCT e.dstport) AS ports,
  sum(e.bytes) AS bytes_out,
  count(*) AS flows,
  min(e.ts) AS first_seen,
  max(e.ts) AS last_seen
FROM egress e
LEFT JOIN resolved r
  ON r.instance = e.instance_id
 AND contains(r.ips, e.dstaddr)
 AND r.ts BETWEEN e.ts - interval '1' day AND e.ts
WHERE r.instance IS NULL
GROUP BY e.instance_id, e.dstaddr
ORDER BY bytes_out DESC
LIMIT 500
