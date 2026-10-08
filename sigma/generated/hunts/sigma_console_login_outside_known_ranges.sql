-- title: Sigma: Console Sign-In From Outside Known Ranges
-- attack: T1078.004
-- purpose: A successful console sign-in came from an address outside the organisation's known ranges. Edit the ranges to your own (the defaults are documentation ranges). Athena-only by design, since CloudWatch filters cannot match CIDRs. (Sigma rule 6d0f5b4e-9a8f-4a52-8f3c-2b6f0c1d7e09, level medium, status experimental)
-- requires: cloudtrail
-- schedule-time-column: ts
-- schedule-baseline: false
-- generated-from: sigma/rules/aws/console_login_outside_known_ranges.yml. Do not edit: change the rule and run scripts/sigma_convert.py.
-- falsepositives: Staff travelling or working from home without the corporate VPN
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  eventsource, eventname, errorcode, awsregion, sourceipaddress, useragent,
  coalesce(useridentity.arn, useridentity.principalid) AS identity,
  requestparameters
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND (((eventname IS NOT NULL AND lower(eventname) = 'consolelogin') AND (json_extract_scalar(responseelements, '$.ConsoleLogin') IS NOT NULL AND lower(json_extract_scalar(responseelements, '$.ConsoleLogin')) = 'success')) AND (NOT (coalesce(${replace(ip_key, "IP_IN", "sourceipaddress")} BETWEEN '00000000000000000000ffffc0000200' AND '00000000000000000000ffffc00002ff', FALSE) OR coalesce(${replace(ip_key, "IP_IN", "sourceipaddress")} BETWEEN '20010db8000000000000000000000000' AND '20010db8ffffffffffffffffffffffff', FALSE))))
ORDER BY ts DESC
LIMIT 500
