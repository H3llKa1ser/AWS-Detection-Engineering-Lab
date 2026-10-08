-- title: Egress to public IPs the instance never resolved through DNS
-- attack: TA0011 Command and Control (hard-coded infrastructure) / T1071 Application Layer Protocol
-- purpose: Accepted connections from an instance to public IPs that no DNS answer to that instance returned in the prior 24 hours. Malware with hard-coded IPs skips DNS; most software does not.
-- requires: flow,dns
-- schedule-time-column: first_seen
-- schedule-baseline: false
-- Joins flow logs to Resolver query logs from the same VPCs. An instance using its own resolver instead of the Route 53 Resolver will appear here too, which is worth knowing.
-- Addresses are compared as canonical keys, so an AAAA answer written as 2001:db8::1 matches a flow to 2001:0db8:0:0:0:0:0:1.
WITH ${internal_nets},
egress AS (
  SELECT instance_id, dstaddr, dstport, bytes, from_unixtime(start) AS ts
  FROM "${database}"."${flow_table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND action = 'ACCEPT'
    AND flow_direction = 'egress'
    AND coalesce(instance_id, '-') <> '-'
    AND coalesce(pkt_dst_aws_service, '-') = '-'
),
internal_addrs AS (
  SELECT DISTINCT d.dstaddr AS addr
  FROM (SELECT DISTINCT dstaddr FROM egress) d
  JOIN internal_nets n ON ${replace(ip_key, "IP_IN", "d.dstaddr")} BETWEEN n.lo AND n.hi
),
external AS (
  SELECT e.*, ${replace(ip_key, "IP_IN", "e.dstaddr")} AS dst_key
  FROM egress e
  WHERE dstaddr NOT IN (SELECT addr FROM internal_addrs)
),
answers AS (
  SELECT
    srcids.instance AS instance,
    from_iso8601_timestamp(query_timestamp) AS ts,
    t.ip
  FROM "${database}"."${dns_table}"
  CROSS JOIN UNNEST(transform(answers, a -> a.rdata)) AS t (ip)
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day - interval '1' day, '%Y/%m/%d')
),
resolved AS (
  SELECT instance, ts, ${replace(ip_key, "IP_IN", "ip")} AS ip_key
  FROM answers
)
SELECT
  e.instance_id,
  e.dstaddr,
  array_agg(DISTINCT e.dstport) AS ports,
  sum(e.bytes) AS bytes_out,
  count(*) AS flows,
  min(e.ts) AS first_seen,
  max(e.ts) AS last_seen
FROM external e
LEFT JOIN resolved r
  ON r.instance = e.instance_id
 AND r.ip_key = e.dst_key
 AND r.ts BETWEEN e.ts - interval '1' day AND e.ts
WHERE r.instance IS NULL
GROUP BY e.instance_id, e.dstaddr
ORDER BY bytes_out DESC
LIMIT 500
