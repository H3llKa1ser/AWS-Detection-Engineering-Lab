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
   response) is behind a flag and defaults off.

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
