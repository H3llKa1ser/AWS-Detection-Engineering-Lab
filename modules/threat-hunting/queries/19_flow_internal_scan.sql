-- title: Internal scanning or lateral-movement sweep
-- attack: T1046 Network Service Discovery / TA0008 Lateral Movement
-- purpose: Internal sources that contacted 20+ internal hosts or 50+ ports in one hour: a compromised host mapping what it can reach next.
-- requires: flow
-- schedule-time-column: hour
-- schedule-baseline: false
-- Uses egress records (logged at the source interface), so each connection is counted once. Monitoring, backup and discovery tools also sweep: allow-list them by srcaddr.
SELECT
  srcaddr,
  instance_id,
  date_trunc('hour', from_unixtime(start)) AS hour,
  count(DISTINCT dstaddr) AS hosts,
  count(DISTINCT dstport) AS ports,
  count_if(action = 'REJECT') AS rejected,
  count(*) AS flows,
  min(dstport) AS lowest_port,
  max(dstport) AS highest_port
FROM "${database}"."${flow_table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND flow_direction = 'egress'
  AND regexp_like(srcaddr, '^(10[.]|172[.](1[6-9]|2[0-9]|3[01])[.]|192[.]168[.]|169[.]254[.]|127[.]|100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.])')
  AND regexp_like(dstaddr, '^(10[.]|172[.](1[6-9]|2[0-9]|3[01])[.]|192[.]168[.]|169[.]254[.]|127[.]|100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.])')
GROUP BY 1, 2, 3
HAVING count(DISTINCT dstaddr) >= 20 OR count(DISTINCT dstport) >= 50
ORDER BY hosts DESC, ports DESC
LIMIT 500
