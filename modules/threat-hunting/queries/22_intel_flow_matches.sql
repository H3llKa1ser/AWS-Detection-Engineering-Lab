-- title: Network traffic to or from threat-intel IPs and ranges
-- attack: TA0011 Command and Control / TA0010 Exfiltration / TA0001 Initial Access (by indicator)
-- purpose: Flows where the remote end (destination of egress, source of ingress) matches an active IP or CIDR indicator, with the indicator's source, confidence and reason.
-- requires: flow,intel
-- schedule-time-column: last_seen
-- schedule-baseline: false
-- Direction is from your interface's point of view. An outbound connection's replies are logged as ingress, so an ingress row next to an egress row for the same IP is usually reply traffic, not an inbound attack.
-- New indicators are retro-hunted over the full lookback automatically when the indicator set changes; the daily run covers new traffic.
WITH ${intel_active},
flows AS (
  SELECT
    instance_id, flow_direction, action, dstport, bytes,
    CASE WHEN flow_direction = 'egress' THEN dstaddr ELSE srcaddr END AS remote_ip,
    from_unixtime(start) AS ts
  FROM "${database}"."${flow_table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
),
flows_int AS (
  SELECT *, (TRY_CAST(split_part(remote_ip, '.', 1) AS bigint) * 16777216 + TRY_CAST(split_part(remote_ip, '.', 2) AS bigint) * 65536 + TRY_CAST(split_part(remote_ip, '.', 3) AS bigint) * 256 + TRY_CAST(split_part(remote_ip, '.', 4) AS bigint)) AS remote_int
  FROM flows
  WHERE regexp_like(remote_ip, '^[0-9]{1,3}([.][0-9]{1,3}){3}$')
)
SELECT
  f.instance_id,
  f.remote_ip,
  f.flow_direction AS direction,
  i.indicator, i.source, i.confidence, i.description,
  count(*) AS flows,
  count_if(f.action = 'ACCEPT') AS accepted,
  count_if(f.action = 'REJECT') AS rejected,
  sum(f.bytes) AS bytes,
  array_agg(DISTINCT f.dstport) AS dst_ports,
  min(f.ts) AS first_seen,
  max(f.ts) AS last_seen
FROM flows_int f
JOIN intel i ON i.kind = 'ip' AND f.remote_int BETWEEN i.lo AND i.hi
GROUP BY f.instance_id, f.remote_ip, f.flow_direction, i.indicator, i.source, i.confidence, i.description, i.confidence_rank
ORDER BY i.confidence_rank DESC, accepted DESC, bytes DESC
LIMIT 500
