# Validating the pipeline

Detections you have not tested are detections you do not have. Three levels,
cheapest first.

## Level 1 — GuardDuty sample findings

Generates one sample of every GuardDuty finding type. Exercises the
GuardDuty → EventBridge → SNS path end to end without any real attacker activity.

```bash
./scripts/generate-findings.sh
```

Under the hood: `aws guardduty create-sample-findings --detector-id <id>
--finding-types <types>`.

## Level 2 — Trip CloudTrail metric filters by hand

Each action below should produce the named alarm within ~5 minutes. All are safe
and reversible.

| Action | Detection tripped |
|--------|-------------------|
| `aws ec2 create-security-group --group-name detlab-test --description test` | security_group_changes |
| `aws iam create-policy --policy-name detlab-test --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:ListAllMyBuckets","Resource":"*"}]}'` (clean up with `aws iam delete-policy --policy-arn <arn>`) | iam_policy_changes |
| Sign in to the console as an IAM user with MFA disabled | console_signin_no_mfa |
| `aws s3api put-bucket-acl ...` on a test bucket | s3_policy_changes |

Remember to clean up the test resources afterwards.

## Level 2b — Network and DNS detections

### DNS (fully self-contained)

```bash
terraform apply -var deploy_traffic_generator=true
```

This launches a hardened t3.micro in the isolated lab VPC that, every 15
minutes, sends to the Route 53 Resolver:

| Traffic | Expected alarm |
|---------|----------------|
| 80 random high-entropy `.com`/`.net`/`.info` lookups | `dns_nxdomain_spike` (unless Advanced blocks them first; see below) |
| 40 word-triple `.com` lookups | Dictionary-DGA shape for Advanced |
| 150 TXT lookups with 40-char random labels | `dns_txt_query_spike` (and adds to the NXDOMAIN count) |
| Lookups of public mining-pool hostnames | `dns_mining_pool_lookup`, plus `dns_firewall_block` (they are on the default custom blocklist). With `dns_firewall_block_domains = []`, expect a real GuardDuty `CryptoCurrency:EC2/BitcoinTool.B!DNS` finding instead; I have not verified whether GuardDuty still raises it when the query is blocked |
| One `.onion` lookup | `dns_onion_lookup` |
| AWS's test domains for the managed lists (`controldomain1.{botnetlist,malwarelist,aggregatelist}.firewall.route53resolver.us-east-1.amazonaws.com`) | `dns_firewall_block`: each attributed to its own list |

It only *resolves names*; it has no internet path and never contacts a mining
pool or Tor. Allow up to ~10 minutes for the first alarms (instance boot plus
log delivery). Confirm the raw records with:

```bash
aws logs tail /detlab/route53-resolver-queries --since 15m
```

To confirm DNS Firewall is enforcing, not just logging, look for blocked
records and their answers:

```bash
aws logs filter-log-events --log-group-name /detlab/route53-resolver-queries \
  --filter-pattern '{ $.firewall_rule_action = "BLOCK" }' --max-items 5
```

Unblocked, AWS's test domains resolve to `1.2.3.4`. Blocked with the default
`NODATA` response, the record shows `rcode` `NOERROR` and no answer. Switch a list
to `ALERT` in `dns_firewall_managed_lists` and apply: its test domain then resolves
to `1.2.3.4` again and `dns_firewall_alert` fires instead.

### DNS Firewall Advanced (best effort)

AWS publishes test domains for the managed lists, not for Advanced, which is
behavioural. The generator's DGA, dictionary-DGA and tunnelling bursts have the
right *shape*, but whether they cross a given confidence threshold is AWS's call.
To give them the best chance:

```bash
terraform apply \
  -var deploy_traffic_generator=true \
  -var 'dns_firewall_advanced_protections=[{protection="DGA",action="ALERT",confidence="LOW"},{protection="DICTIONARY_DGA",action="ALERT",confidence="LOW"},{protection="DNS_TUNNELING",action="ALERT",confidence="LOW"}]'
```

`ALERT` keeps the queries answered so you can compare. Then check:

```bash
aws logs tail /aws/events/detlab-dns-firewall-advanced --since 30m
```

If events appear, the matching `detlab-dns_firewall_advanced_*` alarm should go
to ALARM within one 5-minute period. If nothing appears after a few cycles,
Advanced simply did not flag this synthetic traffic at that confidence. The
rules, routing and alarms are still in place, and real DGA malware or a real
tunnelling tool (e.g. `dnscat2` or `iodine` against a domain you own, from a
sandbox) is the definitive test.

**Expect `dns_nxdomain_spike` to go quiet** if Advanced blocks the DGA burst: with
the `NODATA` block response those queries are logged as `NOERROR`. That is
prevention working, not a broken detection.

Turn it off when done: `terraform apply -var deploy_traffic_generator=false`.

### VPC Flow Logs (needs a VPC with real traffic)

The lab VPC has no inbound or outbound path, so flow detections will stay quiet
there. Add a sandbox VPC that has an internet-facing instance:

```bash
terraform apply -var 'monitored_vpc_ids=["vpc-0123456789abcdef0"]'
```

| Action | Expected alarm |
|--------|----------------|
| Leave an instance with a public IP and port 22 closed for a few hours | `flow_ssh_rejected_ingress` (internet scanners will do the rest) |
| `nmap -Pn -p1-1000 <public-ip>` from a host you control, against your own instance | `flow_reject_spike` |
| From the instance: `nc -zv -w2 <a host you own> 445` | `flow_egress_smb_accepted` (if the instance's SG allows egress 445) |

Only scan addresses you own.

To check a flow pattern against real records before waiting on an alarm, take
it from `terraform output -json` (detections module output `rendered_patterns`)
and paste it into **CloudWatch → Log groups → /detlab/vpc-flow-logs → Metric
filters → Create → Test pattern**.

## Threat-hunting layer

### Offline (no AWS)

```bash
pip install -r tests/hunts/requirements.txt
python3 tests/hunts/test_hunts.py     # expect: all passed
```

### In the account

After `terraform apply`, CloudTrail needs a few minutes to deliver its first
files. Then, in the `detlab-threat-hunting` workgroup:

```sql
SELECT dt, region, count(*) AS events
FROM detlab_security.cloudtrail
WHERE dt >= date_format(current_date - interval '1' day, '%Y/%m/%d')
GROUP BY 1, 2
ORDER BY 1 DESC, 3 DESC
```

Rows for today mean the table, projection, permissions and KMS access all work.
An empty result with no error usually means no logs yet; an `Access Denied`
names the missing permission (bucket, KMS key or results bucket). Run it as an
identity with only the hunter policy attached to prove that policy is sufficient.

To see a hunt fire for real, run one of the Level 2 actions (for example
`aws ec2 create-security-group ...`) and check hunt 06, or create and delete an
access key for a test user from another user and check hunt 05 the next time
CloudTrail delivers (typically within 5-15 minutes).

## Network log lake

Flow logs reach S3 every few minutes after there is traffic (the lab VPC has
little; the traffic generator or a monitored VPC helps). DNS records arrive
when Firehose flushes, every 5 minutes by default. Then, in the hunting
workgroup:

```sql
SELECT 'flow' AS source, dt, count(*) AS records FROM detlab_security.vpc_flow_logs
WHERE dt >= date_format(current_date - interval '1' day, '%Y/%m/%d') GROUP BY 1, 2
UNION ALL
SELECT 'dns', dt, count(*) FROM detlab_security.resolver_query_logs
WHERE dt >= date_format(current_date - interval '1' day, '%Y/%m/%d') GROUP BY 1, 2
```

If DNS shows nothing, check in this order:

1. `aws s3 ls s3://<network-bucket>/route53resolver-errors/ --recursive`. Files
   here mean Firehose received records but could not convert them; the
   CloudWatch log group `/<prefix>/firehose/dns-to-parquet` says why.
2. The Firehose stream's `IncomingRecords` metric. Zero means Resolver is not
   delivering: confirm the stream still has the tag `LogDeliveryEnabled=true`
   and the `<prefix>-dns-query-logs-firehose` config is associated with the VPC.

If flow shows nothing, check that the VPC has an S3 flow log
(`aws ec2 describe-flow-logs --filter Name=log-destination-type,Values=s3`) with
no `DeliverLogsErrorMessage`.

With the traffic generator running, hunts 15-17 have data to chew on; whether
its synthetic patterns cross their thresholds depends on timing (hunt 15 needs
12+ evenly spaced lookups of one name, which the generator's 15-minute cycle
produces after about 3 hours).

## Threat intelligence

### Offline (no AWS)

```bash
python3 tests/intel/test_indicators.py   # curation rules, merge mirror, importer
python3 tests/hunts/test_hunts.py         # includes intel hunts and the canary end to end
```

### In the account

1. After `terraform apply`, `terraform output threat_intel` shows the table and
   indicator counts per source.
2. The first upload already triggered a retro-hunt: the Step Functions console
   shows an execution started by EventBridge, running `retro/22..24`.
3. With the traffic generator running, hunt 23 finds
   `beacon.intel-canary.invalid` (matched by the canary indicator
   `intel-canary.invalid`) once DNS logs reach the lake. In the daily run it
   arrives as `hunt findings: 23_intel_dns_matches`.
4. To watch a retro-hunt fire: add a test indicator for something you know
   happened in the last 30 days (for example the public IP you ran the CLI from,
   as an `ipv4` row with a short expiry), apply, and expect
   `hunt findings: retro/24_intel_cloudtrail_source_ip`. Remove the row
   afterwards.

## IPv6

Offline: `python3 tests/hunts/test_ip_keys.py` (SQL vs Python `ipaddress`).

In the account: `terraform output internal_cidrs` should list the lab VPC's
IPv4 CIDR and its Amazon-provided IPv6 /56. To check IPv6 indicator matching
end to end without real traffic, add a short-lived `ipv6` indicator for the
public IPv6 address of a dual-stack machine you control, call any AWS API from
it over IPv6 (enable the CLI's dual-stack endpoints with
`AWS_USE_DUALSTACK_ENDPOINT=true`, for a service that offers one in your
region), and expect
`retro/24_intel_cloudtrail_source_ip` after apply. Remove the row afterwards.

## Scheduled hunts

### Offline (no AWS)

```bash
pip install -r tests/hunts/requirements.txt -r tests/scheduled/requirements.txt
python3 tests/hunts/test_hunts.py              # all passed: hunts + scheduled variants
python3 tests/scheduled/test_state_machine.py  # all passed: state machine data flow

# Schema-validate the state machine definition, rendered as the tests render it (Node.js):
python3 -c "import json,sys; sys.path.insert(0,'tests/scheduled'); import test_state_machine as t; print(json.dumps(t.render()))" > /tmp/hunts.asl.json
npx asl-validator --json-path /tmp/hunts.asl.json
```

### In the account

1. Trigger an event a scheduled hunt watches, e.g. create an access key for a
   test user *from another user* (hunt 05) or call
   `aws guardduty create-ip-set ...` (hunt 06). Wait about 15 minutes for
   CloudTrail delivery, plus the one-hour lag.
2. Run the schedule now: `$(terraform output -raw run_scheduled_hunts_now)`.
3. Expect one `[detlab] hunt findings: ...` email per hunt with findings, and
   nothing for clean hunts. Running it again the same day re-reports the same
   window (manual runs are not de-duplicated; the daily schedule is).
4. To see a failure alert, temporarily set `hunting_bytes_scanned_cutoff` to
   the 10 MB minimum and run a baseline hunt.
5. To test the dead man's switch without waiting two days, disable the schedule
   (`aws scheduler update-schedule ... --state DISABLED`) and watch
   `detlab-scheduled_hunts_not_running` go to ALARM after the second empty day.

## Level 3 — Adversary emulation (real findings)

Use [Stratus Red Team](https://github.com/DataDog/stratus-red-team) for genuine
TTPs that trigger *real* GuardDuty findings, not samples:

```bash
stratus list
stratus detonate aws.credential-access.ec2-get-password-data
stratus detonate aws.defense-evasion.cloudtrail-stop
stratus cleanup --all
```

`aws.defense-evasion.cloudtrail-stop` is a good end-to-end test: it should trip
both your `cloudtrail_config_changes` metric filter and a GuardDuty finding, and
show up in hunt 06. Afterwards, run hunts 03 and 04 against the Stratus
identity: its setup and detonation leave a discovery footprint worth seeing.
