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
