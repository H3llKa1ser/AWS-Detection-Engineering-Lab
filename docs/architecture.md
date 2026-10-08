# Architecture

## Design principles

1. **Everything is telemetry first.** No detection exists without a reliable log
   source. CloudTrail is the spine; GuardDuty, Config and Security Hub layer on
   top; metric filters read the same CloudTrail stream from CloudWatch Logs.
2. **One alerting fabric.** Every signal source — custom alarms, GuardDuty,
   Security Hub — publishes to a single SNS topic. Swap the subscriber (email,
   Slack, PagerDuty, a SIEM HTTP endpoint) without touching detections.
3. **Detection-as-code.** Detections are data (`catalogue.tf`), not copy-pasted
   resources. The catalogue is the documentation.
4. **Least privilege, partition-safe.** IAM is scoped per component; ARNs are
   built from `aws_partition` so the code also works in GovCloud / China.
5. **Opt-in blast radius.** Anything that mutates the account (the Lambda
   response) is behind a flag and defaults off. Anything that changes how real
   workloads behave (DNS Firewall on monitored VPCs) is a separate opt-in.

## Data flow

1. API activity is captured by the multi-region CloudTrail and written to both
   an encrypted S3 bucket (durable, validated audit trail) and a CloudWatch Logs
   group (fast stream).
2. The `detections` module attaches 15 metric filters to that log group. A match
   increments a custom metric; an alarm on that metric notifies SNS.
3. GuardDuty and Security Hub run independently and emit findings to the default
   event bus. EventBridge rules filter those findings (severity / label) and
   forward them to the same SNS topic.
4. If response automation is enabled, a tighter EventBridge rule routes a
   specific GuardDuty finding type to a Lambda that remediates and notifies.

## Why metric filters *and* GuardDuty?

They are complementary. GuardDuty is behavioural and ML-driven but opaque and
AWS-owned. Metric filters are deterministic, transparent, cheap, and fully under
your control — you can read exactly what each one matches. A mature detection
practice runs both: managed detection for breadth, custom detection for the
control-plane events you specifically care about.

## Network telemetry layer

### Why own the network logs when GuardDuty already looks at them?

GuardDuty analyses VPC flow and DNS data from an independent AWS-internal feed.
Enabling flow logs or query logging neither feeds nor improves it. What you lose
by relying on GuardDuty alone is *access*: you cannot query that feed, tune its
logic, keep it for a retention period of your choosing, or hunt through it after
an incident. The `vpc-flow-logs` and `dns-query-logging` modules give you the raw
records in CloudWatch Logs so the detection catalogue (and you) can use them.

### VPC Flow Logs

- **Custom v5 format.** The first 14 fields are the AWS default format in the
  default order; eight more add `vpc-id`, `subnet-id`, `instance-id`,
  `tcp-flags`, `type`, `pkt-srcaddr`, `pkt-dstaddr` and `flow-direction`.
  `flow-direction` is what lets a detection tell inbound from outbound without
  knowing the VPC's CIDRs.
- **1-minute aggregation** instead of the 10-minute default, so flow detections
  fire within a few minutes of the activity. Cost is per GB ingested, not per
  record, so this is close to free.
- **The field order is a contract.** `local.flow_fields` in
  `modules/detections/catalogue_network.tf` must list fields in the same order as
  `log_format` in `modules/vpc-flow-logs/main.tf`. Detections declare only the
  fields they filter on and the space-delimited pattern is generated from that
  list, so the contract lives in exactly two places.
- **Known blind spots** (by AWS design): traffic to the Amazon DNS server, the
  instance metadata service (169.254.169.254), Amazon Time Sync, and DHCP is not
  captured. DNS gets its own log source for exactly this reason.

### Route 53 Resolver query logging

- One query log config, associated with every monitored VPC. Records are JSON
  (`query_name`, `query_type`, `rcode`, `answers`, `srcaddr`, `srcids.instance`),
  so DNS detections use JSON metric-filter syntax.
- Delivery uses the CloudWatch Logs vended-logs path. The log-group resource
  policy for `delivery.logs.amazonaws.com` is declared explicitly (scoped by
  `aws:SourceAccount`) rather than left to AWS to create on the fly.
- Only queries sent to the Route 53 Resolver are logged. A workload using its own
  resolver (e.g. hardcoded 8.8.8.8 and an internet path) bypasses this, which is
  itself worth detecting with a flow-log rule on egress UDP/TCP 53 in a VPC that
  has internet egress.

### Encryption

All three log groups (CloudTrail, flow, DNS) are encrypted with the lab CMK when
`kms_encrypt_logs = true`. The key policy grants the CloudWatch Logs service
principal use of the key only for the CloudTrail log group and log groups under
`/<name_prefix>/`.

### The lab VPC

An isolated VPC with one private subnet and no internet gateway or NAT, so it
costs nothing. DNS still works because every VPC can reach the Route 53 Resolver
at its link-local address, which is why the traffic generator can exercise every
DNS detection from inside it. Flow detections need real traffic: point
`monitored_vpc_ids` at a VPC with workloads (or with an internet-facing
instance) to see them fire. The VPC's default security group is managed with no
rules so the lab stays compliant with its own `vpc-default-sg-closed` Config rule.

## DNS Firewall (prevention layer)

### Where it sits

DNS Firewall evaluates every query a protected VPC sends to the Route 53
Resolver, before the Resolver answers. It is the only *preventive* control in
the lab; everything else detects or records. Its verdicts land in the same
Resolver query logs as every other DNS record, so prevention and detection share
one telemetry stream.

### Rule order and attribution

First match wins, lowest priority number first. The allow list sits on top so a
false positive is fixed by adding a domain, never by weakening a block rule.
The specific managed lists (malware, botnet C2) run before the aggregate list,
which is a superset of them: the aggregate rule still catches everything else,
but a hit on a specific list is logged with that list's `firewall_domain_list_id`,
telling the analyst the category without extra lookups. The
`dns_firewall_managed_list_ids` output maps those IDs back to names.

### Resolving managed-list IDs

AWS-managed lists have region-specific IDs, and `hashicorp/aws` has no data
source that finds a domain list by name. The module runs
`modules/dns-firewall/scripts/lookup-managed-domain-lists.sh` (an `external` data
source) which calls `aws route53resolver list-firewall-domain-lists` and returns
the AWS-owned lists. Every ID is then read through the provider with a
postcondition that its name matches and it is AWS-managed, so a wrong or stale ID
fails the plan instead of silently creating a rule against the wrong list.

### Failure modes

- **Fail closed (default).** If DNS Firewall cannot evaluate a query, the query
  is blocked. Right for a security lab; for production, decide per VPC whether a
  DNS outage or an unfiltered query is the worse outcome.
- **Bypass.** DNS Firewall only sees queries sent to the Route 53 Resolver. A
  workload that talks to an external resolver directly (with an internet path)
  bypasses it. Pair it with egress controls that only allow DNS to the Resolver,
  and with the flow-log detection for egress port 53 described in the catalogue
  docs.
- **Not a substitute for GuardDuty.** AWS states the managed lists are an extra
  layer, not a replacement for GuardDuty.

### DNS Firewall Advanced

Domain-list rules are only as current as the feed behind them. Advanced rules
(priorities 400+) carry no list: AWS inspects the query string, its length and
type, and request/response frequency to flag DGA names, dictionary-DGA names and
tunnelling traffic. That covers the gap a list cannot: a fresh domain generated
this morning.

- **Provider.** Advanced rules need `hashicorp/aws` 6.x, where a firewall rule
  takes `dns_threat_protection` and `confidence_threshold` and no longer
  requires a domain list. The provider validates `confidence_threshold` but not
  `dns_threat_protection`, so the root variable validates the protection names
  to catch typos at plan time instead of at apply.
- **Actions.** `BLOCK` or `ALERT`; `ALLOW` is not available for Advanced rules.
- **Confidence.** `LOW` maximises detection and false positives, `HIGH` only
  flags well-corroborated threats. Defaults are `BLOCK` at `MEDIUM`.
- **False positives.** The priority-100 allow list runs before Advanced rules, so
  allow-listing a domain is the override, as AWS documents.

### Advanced verdict telemetry (EventBridge)

The Resolver query-log reference documents `firewall_rule_action`,
`firewall_rule_group_id` and `firewall_domain_list_id`, which tell you a query was
blocked but not by which Advanced detector. DNS Firewall's EventBridge events do
(`detail.firewall-protection` = `DGA`, `DICTIONARY_DGA` or `DNS_TUNNELING`).
DNS Firewall sends them to the default event bus automatically, needs no extra
permissions, and sends the same event for the same domain at most once per six
hours.

Per enabled protection the module creates:

1. an EventBridge rule matching `source: aws.route53resolver`, both
   `DNS Firewall Block` and `DNS Firewall Alert`, and that protection;
2. a target writing raw events to `/aws/events/<prefix>-dns-firewall-advanced`
   (encrypted with the lab CMK; the log-group resource policy only accepts
   writes from these rules), kept as triage evidence;
3. a CloudWatch alarm on the rule's `AWS/Events` `MatchedEvents` metric
   (`RuleName` dimension) to the SNS topic. EventBridge publishes the metric only
   when non-zero, so missing data is treated as not breaching.

Alarming on the metric rather than pointing EventBridge straight at SNS keeps the
lab's thresholded 5-minute model: a tunnelling session that produces hundreds of
new names is one alarm, not hundreds of emails.

These alarms live in the `dns-firewall` module rather than the metric-filter
catalogue because they are driven by an AWS metric, not a log pattern.

## Threat hunting layer (Athena over CloudTrail)

### Detection vs hunting

The metric-filter detections evaluate one event at a time against a pattern,
within minutes. Many attacker behaviours are not visible in one event: a new IP
only means something against a baseline, password spraying is a sequence, a
replayed instance credential is the same session from two places. Those need
history and joins, which is what Athena over the S3 copy of CloudTrail gives.
The two layers share one source of truth (the trail) but read different copies:
CloudWatch Logs for speed, S3 for depth and retention.

### Table design

- **Read in place.** The Glue table points at
  `s3://<cloudtrail-bucket>/AWSLogs/<account>/CloudTrail/`. Nothing is copied or
  converted, so the hunting layer adds no storage and no pipeline to break.
  Digest files live under `CloudTrail-Digest/` and are outside the location.
- **Schema.** AWS's current Athena DDL for CloudTrail with
  `org.apache.hive.hcatalog.data.JsonSerDe` and `CloudTrailInputFormat`.
  `requestparameters`, `responseelements` and `additionaleventdata` are strings
  holding JSON; hunts read them with `json_extract_scalar`.
- **Partition projection** on `region` (enum of the account's enabled regions,
  read at apply time) and `dt` (`yyyy/MM/dd`, from `hunting_projection_start` to
  `NOW`). Athena computes partitions from these rules instead of the catalog, so
  there is no crawler and no partition maintenance, and a new day is queryable
  as soon as CloudTrail writes it. If you enable a new region, re-apply so the
  region enum includes it.
- **`dt` is the delivery day**, used for pruning. Hunts filter on `dt` for cost,
  then on `eventtime` for precision.

### Workgroup controls

`enforce_workgroup_configuration` stops a client from overriding the result
location or encryption. Results land in a dedicated bucket (public access
blocked, TLS-only policy, encrypted with the lab CMK, expiring after
`results_retention_days`), because query results are extracts of CloudTrail and
deserve the same protection. `bytes_scanned_cutoff_per_query` cancels any query
that would scan more than the cap.

### Hunter permissions

`aws_iam_policy.hunter` is created but not attached: attach it to the people or
roles who hunt. It allows queries only in the hunting workgroup, read-only Glue
access to the security database, `s3:GetObject` (no write, no delete) on the
CloudTrail prefix, read/write on the results prefix, and use of the lab key. A
hunter cannot modify the evidence they are searching.

### Saved queries as code

`modules/threat-hunting/queries/*.sql` are Athena SQL templates with a parsed
header (`title`, `attack`, `purpose`). Terraform renders them with the
deployment's database, table and windows (`hunting_lookback_days`,
`hunting_recent_days`) and saves them as named queries. Adding a hunt means
adding a file and a test.

### Query tests

`tests/hunts/test_hunts.py` gives each hunt a planted attack and benign
look-alikes in synthetic CloudTrail, transpiles the rendered query from Athena
SQL to DuckDB with sqlglot, and asserts the exact result. The table schema is
parsed from the module, a meta-test fails if a query has no test, and the suite
has been mutation-checked (removing a key exclusion from a query makes its test
fail). Limits: it does not exercise Athena itself (partition-projection pruning,
JsonSerDe parsing of real files, Trino-specific function edge cases).
