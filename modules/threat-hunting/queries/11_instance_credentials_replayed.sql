-- title: EC2 instance-role credentials used from several source IPs
-- attack: T1552.005 Unsecured Credentials: Cloud Instance Metadata API / T1078.004 Valid Accounts: Cloud Accounts
-- purpose: Instance-role sessions (one per instance) seen from more than one non-AWS source IP, a sign the temporary credentials were taken from IMDS and replayed elsewhere.
-- ec2roledelivery 1.0 means the credentials came from IMDSv1, the version SSRF bugs can reach. Complements GuardDuty InstanceCredentialExfiltration findings.
-- False positives: instances whose egress IP changes (NAT gateway swap, new EIP) or that mix VPC-endpoint (private IP) and internet calls.
SELECT
  useridentity.principalid AS session,
  useridentity.sessioncontext.sessionissuer.arn AS role,
  regexp_extract(useridentity.principalid, 'i-[0-9a-f]+') AS instance_id,
  count(DISTINCT sourceipaddress) AS distinct_source_ips,
  array_agg(DISTINCT sourceipaddress) AS source_ips,
  array_agg(DISTINCT useragent) AS user_agents,
  array_agg(DISTINCT useridentity.sessioncontext.ec2roledelivery) AS imds_version,
  count(*) AS calls,
  min(from_iso8601_timestamp(eventtime)) AS first_seen,
  max(from_iso8601_timestamp(eventtime)) AS last_seen
FROM "${database}"."${table}"
WHERE dt >= date_format(current_date - interval '${lookback_days}' day, '%Y/%m/%d')
  AND useridentity.type = 'AssumedRole'
  AND useridentity.principalid LIKE '%:i-%'
  AND sourceipaddress NOT LIKE '%.amazonaws.com'
  AND sourceipaddress <> 'AWS Internal'
GROUP BY 1, 2, 3
HAVING count(DISTINCT sourceipaddress) > 1
ORDER BY distinct_source_ips DESC
LIMIT 500
