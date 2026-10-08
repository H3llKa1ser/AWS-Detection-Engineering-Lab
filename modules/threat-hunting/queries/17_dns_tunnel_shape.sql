-- title: DNS tunnelling shape (many long, unique subdomains under one parent)
-- attack: T1071.004 Application Layer Protocol: DNS / T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol
-- purpose: Instance and parent-domain pairs with 50+ unique names in one hour and a long average first label: how data looks when it is encoded into DNS names.
-- requires: dns
-- schedule-time-column: hour
-- schedule-baseline: false
-- Complements DNS Firewall Advanced: this also sees ALERT-mode traffic, what happened before a block, and VPCs where Advanced is off.
WITH q AS (
  SELECT
    srcids.instance AS instance,
    date_trunc('hour', from_iso8601_timestamp(query_timestamp)) AS hour,
    query_type,
    regexp_replace(lower(query_name), '[.]$', '') AS name
  FROM "${database}"."${dns_table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND srcids.instance IS NOT NULL
),
labelled AS (
  SELECT instance, hour, query_type, name, split(name, '.') AS labels
  FROM q
  WHERE cardinality(split(name, '.')) >= 3
)
SELECT
  instance,
  hour,
  element_at(labels, -2) || '.' || element_at(labels, -1) AS parent_domain,
  count(DISTINCT name) AS unique_names,
  round(avg(length(element_at(labels, 1))), 1) AS avg_first_label_length,
  array_agg(DISTINCT query_type) AS query_types,
  count(*) AS lookups
FROM labelled
GROUP BY 1, 2, 3
HAVING count(DISTINCT name) >= 50
   AND avg(length(element_at(labels, 1))) >= 20
ORDER BY unique_names DESC
LIMIT 500
