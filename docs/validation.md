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
| `aws iam create-policy --policy-name detlab-test --policy-document '{"Version":"2012-10-17","Statement":[]}'` | iam_policy_changes |
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
| 80 random `*.invalid` lookups | `dns_nxdomain_spike` |
| 150 TXT lookups with 40-char random labels | `dns_txt_query_spike` (and adds to the NXDOMAIN count) |
| Lookups of public mining-pool hostnames | `dns_mining_pool_lookup` **and** a real GuardDuty `CryptoCurrency:EC2/BitcoinTool.B!DNS` finding |
| One `.onion` lookup | `dns_onion_lookup` |

It only *resolves names*; it has no internet path and never contacts a mining
pool or Tor. Allow up to ~10 minutes for the first alarms (instance boot plus
log delivery). Confirm the raw records with:

```bash
aws logs tail /detlab/route53-resolver-queries --since 15m
```

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
