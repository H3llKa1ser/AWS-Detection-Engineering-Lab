-- title: Threat-intel inventory and hygiene
-- attack: Intel hygiene (report, not a hunt)
-- purpose: Indicators per source and type: how many are active, expiring within 14 days, or already expired, and the newest addition. Run before reviews to prune and re-verify.
-- requires: intel
SELECT
  trim(source) AS source,
  lower(trim(type)) AS type,
  count(*) AS indicators,
  count_if(trim(expires) >= date_format(current_date, '%Y-%m-%d')) AS active,
  count_if(trim(expires) >= date_format(current_date, '%Y-%m-%d')
           AND trim(expires) < date_format(current_date + interval '14' day, '%Y-%m-%d')) AS expiring_14d,
  count_if(trim(expires) < date_format(current_date, '%Y-%m-%d')) AS expired,
  max(trim(added)) AS newest_added
FROM "${database}"."${intel_table}"
GROUP BY 1, 2
ORDER BY expired DESC, expiring_14d DESC, source
