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
both your `cloudtrail_config_changes` metric filter and a GuardDuty finding.
