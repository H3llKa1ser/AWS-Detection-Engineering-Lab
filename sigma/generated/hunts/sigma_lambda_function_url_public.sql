-- title: Sigma: Lambda Function URL Created Without Authentication
-- attack: T1190
-- purpose: A Lambda function URL was created or changed with auth type NONE, exposing the function to the internet without IAM authentication. (Sigma rule 6d0f5b4e-9a8f-4a52-8f3c-2b6f0c1d7e05, level medium, status experimental)
-- requires: cloudtrail
-- schedule-time-column: ts
-- schedule-baseline: false
-- generated-from: sigma/rules/aws/lambda_function_url_public.yml. Do not edit: change the rule and run scripts/sigma_convert.py.
-- falsepositives: Public webhooks that validate requests themselves
SELECT
  from_iso8601_timestamp(eventtime) AS ts,
  eventsource, eventname, errorcode, awsregion, sourceipaddress, useragent,
  coalesce(useridentity.arn, useridentity.principalid) AS identity,
  requestparameters
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND ((eventsource IS NOT NULL AND lower(eventsource) = 'lambda.amazonaws.com') AND ((eventname IS NOT NULL AND lower(eventname) LIKE 'createfunctionurlconfig%' ESCAPE '!') OR (eventname IS NOT NULL AND lower(eventname) LIKE 'updatefunctionurlconfig%' ESCAPE '!')) AND (json_extract_scalar(requestparameters, '$.authType') IS NOT NULL AND lower(json_extract_scalar(requestparameters, '$.authType')) = 'none'))
ORDER BY ts DESC
LIMIT 500
