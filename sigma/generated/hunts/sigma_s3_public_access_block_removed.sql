-- title: Sigma: S3 Public Access Block Removed
-- attack: T1537 / T1562
-- purpose: A bucket- or account-level S3 Block Public Access configuration was deleted, the usual first step before exposing data publicly. (Sigma rule 6d0f5b4e-9a8f-4a52-8f3c-2b6f0c1d7e02, level high, status experimental)
-- requires: cloudtrail
-- schedule-time-column: ts
-- schedule-baseline: false
-- generated-from: sigma/rules/aws/s3_public_access_block_removed.yml. Do not edit: change the rule and run scripts/sigma_convert.py.
-- falsepositives: Buckets intentionally made public (static websites behind review)
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  eventsource, eventname, errorcode, awsregion, sourceipaddress, useragent,
  coalesce(useridentity.arn, useridentity.principalid) AS identity,
  requestparameters
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND (((eventsource IS NOT NULL AND lower(eventsource) = 's3.amazonaws.com') OR (eventsource IS NOT NULL AND lower(eventsource) = 's3-control.amazonaws.com')) AND (eventname IS NOT NULL AND lower(eventname) LIKE 'delete%' ESCAPE '!') AND (eventname IS NOT NULL AND lower(eventname) LIKE '%publicaccessblock' ESCAPE '!'))
ORDER BY ts DESC
LIMIT 500
