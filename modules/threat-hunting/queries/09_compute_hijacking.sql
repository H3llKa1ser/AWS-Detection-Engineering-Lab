-- title: GPU, accelerated or very large instances launched (cryptomining shape)
-- attack: T1496 Resource Hijacking
-- purpose: RunInstances requests for GPU/accelerator families, metal or 12xlarge+ sizes, or 5+ instances at once, including failures, since quota errors are a signal too.
WITH launches AS (
  SELECT
    from_iso8601_timestamp(eventtime) AS ts,
    awsregion,
    coalesce(useridentity.arn, useridentity.principalid) AS actor,
    json_extract_scalar(requestparameters, '$.instanceType') AS instance_type,
    TRY_CAST(json_extract_scalar(requestparameters, '$.instancesSet.items[0].maxCount') AS integer) AS max_count,
    errorcode,
    sourceipaddress
  FROM "${database}"."${table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND eventsource = 'ec2.amazonaws.com'
    AND eventname = 'RunInstances'
)
SELECT ts, awsregion, actor, instance_type, max_count, errorcode, sourceipaddress
FROM launches
WHERE regexp_like(instance_type, '^(p[0-9]|g[0-9]|inf[0-9]|trn[0-9]|dl[0-9]|vt[0-9]|f[0-9])')
   OR regexp_like(instance_type, '[.](metal|(1[2-9]|[2-9][0-9])xlarge)')
   OR max_count >= 5
ORDER BY ts DESC
LIMIT 500
