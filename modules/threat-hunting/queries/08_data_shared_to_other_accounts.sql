-- title: Snapshots, images and buckets shared outside the account
-- attack: T1537 Transfer Data to Cloud Account
-- purpose: Sharing and replication calls that expose data to other accounts or to everyone, with the foreign account IDs pulled out of the request.
-- schedule-time-column: ts
-- schedule-baseline: false
-- Account IDs are matched as standalone 12-digit numbers, so longer numbers such as epoch-millisecond timestamps do not produce false matches.
WITH shares AS (
  SELECT
    from_iso8601_timestamp(eventtime) AS ts,
    eventsource,
    eventname,
    coalesce(useridentity.arn, useridentity.principalid) AS actor,
    recipientaccountid,
    sourceipaddress,
    requestparameters,
    regexp_extract_all(requestparameters, '\b[0-9]{12}\b') AS account_ids_in_request
  FROM "${database}"."${table}"
  WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
    AND errorcode IS NULL
    AND (
         (eventsource = 'ec2.amazonaws.com' AND eventname IN ('ModifySnapshotAttribute', 'ModifyImageAttribute'))
      OR (eventsource = 'rds.amazonaws.com' AND eventname IN ('ModifyDBSnapshotAttribute', 'ModifyDBClusterSnapshotAttribute'))
      OR (eventsource = 's3.amazonaws.com' AND eventname IN ('PutBucketReplication', 'PutBucketPolicy', 'PutBucketAcl'))
    )
)
SELECT
  ts, eventname, actor,
  filter(account_ids_in_request, x -> x <> recipientaccountid) AS foreign_accounts,
  requestparameters LIKE '%"all"%' OR requestparameters LIKE '%"Principal":"*"%' OR requestparameters LIKE '%"AWS":"*"%' OR requestparameters LIKE '%AllUsers%' AS public,
  sourceipaddress,
  requestparameters
FROM shares
WHERE cardinality(filter(account_ids_in_request, x -> x <> recipientaccountid)) > 0
   OR requestparameters LIKE '%"all"%'
   OR requestparameters LIKE '%"Principal":"*"%'
   OR requestparameters LIKE '%"AWS":"*"%'
   OR requestparameters LIKE '%AllUsers%'
ORDER BY ts DESC
LIMIT 500
