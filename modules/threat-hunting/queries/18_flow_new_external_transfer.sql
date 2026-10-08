-- title: Large transfer to a public IP the instance never used before
-- attack: T1048 Exfiltration Over Alternative Protocol / T1567 Exfiltration Over Web Service
-- purpose: Accepted egress of 100 MiB+ in the recent window from an instance to a public IP it did not contact in the baseline window. AWS service endpoints are excluded.
-- requires: flow
-- schedule-time-column: first_seen
-- schedule-baseline: true
-- External means outside internal_nets: private and special IPv4/IPv6 ranges plus the monitored VPCs' own CIDRs. VPC IPv6 addresses are globally routable, so only the VPC CIDR identifies them as internal.
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
  SELECT * FROM egress WHERE dstaddr NOT IN (SELECT addr FROM internal_addrs)
),
baseline AS (
  SELECT DISTINCT instance_id, dstaddr
  FROM external
  WHERE ts < current_timestamp - interval '${recent_days}' day
),
recent AS (
  SELECT
    instance_id, dstaddr,
    sum(bytes) AS bytes_out,
    array_agg(DISTINCT dstport) AS ports,
    min(ts) AS first_seen,
    max(ts) AS last_seen
  FROM external
  WHERE ts >= current_timestamp - interval '${recent_days}' day
  GROUP BY instance_id, dstaddr
)
SELECT
  r.instance_id, r.dstaddr,
  round(r.bytes_out / 1048576.0, 1) AS mib_out,
  r.ports, r.first_seen, r.last_seen
FROM recent r
LEFT JOIN baseline b ON r.instance_id = b.instance_id AND r.dstaddr = b.dstaddr
WHERE b.instance_id IS NULL
  AND r.bytes_out >= 104857600
ORDER BY r.bytes_out DESC
LIMIT 500
