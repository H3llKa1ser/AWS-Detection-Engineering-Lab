-- title: Investigation: one instance across CloudTrail, DNS and flow logs
-- attack: Investigation pivot (any technique)
-- purpose: One ordered timeline of what an instance did and what was done to it: API calls with its role credentials or naming it, DNS lookups, and network flows. Replace i-0123456789abcdef0 before running.
-- requires: cloudtrail,flow,dns
SELECT * FROM (
  SELECT
    from_iso8601_timestamp(eventtime) AS ts,
    CASE WHEN useridentity.principalid LIKE '%:i-0123456789abcdef0'
         THEN 'cloudtrail: by instance' ELSE 'cloudtrail: about instance' END AS source,
    eventname AS activity,
    eventsource || ' from ' || coalesce(sourceipaddress, '?') || ' by ' || coalesce(useridentity.arn, useridentity.principalid, '?') AS detail,
    coalesce(errorcode, 'ok') AS outcome
  FROM "${database}"."${table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND (useridentity.principalid LIKE '%:i-0123456789abcdef0'
         OR strpos(coalesce(requestparameters, ''), 'i-0123456789abcdef0') > 0
         OR strpos(coalesce(responseelements, ''), 'i-0123456789abcdef0') > 0)

  UNION ALL

  SELECT
    from_iso8601_timestamp(query_timestamp),
    'dns',
    coalesce(query_type, '?') || ' ' || coalesce(query_name, '?'),
    'rcode ' || coalesce(rcode, '?') || coalesce(' / DNS Firewall ' || firewall_rule_action, ''),
    coalesce(firewall_rule_action, rcode, '?')
  FROM "${database}"."${dns_table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND srcids.instance = 'i-0123456789abcdef0'

  UNION ALL

  SELECT
    from_unixtime(start),
    'flow',
    coalesce(flow_direction, '?') || ' ' || coalesce(action, '?'),
    coalesce(srcaddr, '?') || ':' || coalesce(CAST(srcport AS varchar), '?') || ' -> '
      || coalesce(dstaddr, '?') || ':' || coalesce(CAST(dstport AS varchar), '?')
      || ' ' || coalesce(CAST(bytes AS varchar), '?') || ' bytes',
    coalesce(action, '?')
  FROM "${database}"."${flow_table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND instance_id = 'i-0123456789abcdef0'
) AS timeline
ORDER BY ts
LIMIT 5000
