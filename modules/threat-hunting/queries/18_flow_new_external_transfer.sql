-- title: Large transfer to a public IP the instance never used before
-- attack: T1048 Exfiltration Over Alternative Protocol / T1567 Exfiltration Over Web Service
-- purpose: Accepted egress of 100 MiB+ in the recent window from an instance to a public IP it did not contact in the baseline window. AWS service endpoints are excluded.
-- requires: flow
-- schedule-time-column: first_seen
-- schedule-baseline: true
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
baseline AS (
  SELECT DISTINCT instance_id, dstaddr
  FROM egress
  WHERE ts < current_timestamp - interval '${recent_days}' day
),
recent AS (
  SELECT
    instance_id, dstaddr,
    sum(bytes) AS bytes_out,
    array_agg(DISTINCT dstport) AS ports,
    min(ts) AS first_seen,
    max(ts) AS last_seen
  FROM egress
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
