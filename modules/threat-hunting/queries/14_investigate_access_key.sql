-- title: Investigation: full timeline for one access key
-- attack: Investigation pivot (any technique)
-- purpose: Everything one access key did, in order. Replace AKIAIOSFODNN7EXAMPLE with the key from an alert or hunt before running.
-- Works for long-term keys (AKIA...) and session keys (ASIA...). Widen the dt filter if the key is older than the window.
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  eventsource,
  eventname,
  errorcode,
  awsregion,
  sourceipaddress,
  useragent,
  coalesce(useridentity.arn, useridentity.principalid) AS identity,
  requestparameters,
  resources
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND useridentity.accesskeyid = 'AKIAIOSFODNN7EXAMPLE'
ORDER BY ts
LIMIT 5000
