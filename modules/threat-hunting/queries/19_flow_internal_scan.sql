-- title: Internal scanning or lateral-movement sweep
-- attack: T1046 Network Service Discovery / TA0008 Lateral Movement
-- purpose: Internal sources that contacted 20+ internal hosts or 50+ ports in one hour: a compromised host mapping what it can reach next.
-- requires: flow
-- schedule-time-column: hour
-- schedule-baseline: false
-- Uses egress records (logged at the source interface), so each connection is counted once. Monitoring, backup and discovery tools also sweep: allow-list them by srcaddr.
-- Internal means inside internal_nets (private/special ranges plus the monitored VPCs' IPv4 and IPv6 CIDRs), so IPv6 sweeps inside a dual-stack VPC count too.
WITH ${internal_nets},
flows AS (
  SELECT srcaddr, dstaddr, dstport, action, instance_id, from_unixtime(start) AS ts
  FROM "${database}"."${flow_table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND flow_direction = 'egress'
),
addrs AS (
  SELECT srcaddr AS addr FROM flows
  UNION
  SELECT dstaddr FROM flows
),
internal_addrs AS (
  SELECT DISTINCT a.addr
  FROM addrs a
  JOIN internal_nets n ON ${replace(ip_key, "IP_IN", "a.addr")} BETWEEN n.lo AND n.hi
)
SELECT
  srcaddr,
  instance_id,
  date_trunc('hour', ts) AS hour,
  count(DISTINCT dstaddr) AS hosts,
  count(DISTINCT dstport) AS ports,
  count_if(action = 'REJECT') AS rejected,
  count(*) AS flows,
  min(dstport) AS lowest_port,
  max(dstport) AS highest_port
FROM flows
WHERE srcaddr IN (SELECT addr FROM internal_addrs)
  AND dstaddr IN (SELECT addr FROM internal_addrs)
GROUP BY 1, 2, 3
HAVING count(DISTINCT dstaddr) >= 20 OR count(DISTINCT dstport) >= 50
ORDER BY hosts DESC, ports DESC
LIMIT 500
