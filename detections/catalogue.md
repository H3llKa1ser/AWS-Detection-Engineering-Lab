# Detection catalogue

Documentation for the detections defined as code in
[`catalogue.tf`](../modules/detections/catalogue.tf) (CloudTrail) and
[`catalogue_network.tf`](../modules/detections/catalogue_network.tf) (VPC Flow
Logs, Route 53 Resolver query logs, DNS Firewall verdicts).
The Terraform map is the source of truth; keep this table in sync when you add
or remove entries.

Each detection is a CloudWatch Logs **metric filter** over the log group for its
telemetry source plus a **metric alarm** that notifies the shared SNS topic once
the detection's `threshold` is reached within a 5-minute window (default 1).

See the [README detection tables](../README.md#detection-catalogue) for the full
CIS + MITRE ATT&CK mapping.

## Tuning notes

- **Thresholds**: all detections alarm at the first event (`threshold = 1`).
  For noisy controls (e.g. `security_group_changes` in an active account) raise
  the threshold or lengthen the period to cut false positives.
- **Suppression**: legitimate automation (Terraform, CI roles) will trip
  control-plane detections. Prefer filtering by `userIdentity.arn` in the metric
  filter pattern over disabling the detection.
- **Coverage gaps**: metric filters only see what CloudTrail logs. Data-plane
  events (S3 object access, Lambda invokes) require CloudTrail data events, which
  are not enabled here by default for cost reasons.

## Writing a flow-log detection

```hcl
flow_egress_dns_bypass = {
  source      = "vpc_flow"
  description = "Outbound DNS to a resolver other than Route 53 Resolver"
  attack      = "T1071.004 Application Layer Protocol: DNS"
  threshold   = 1
  flow_match  = { action = "=\"ACCEPT\"", dstport = "=\"53\"", flow_direction = "=\"egress\"" }
}
```

Field names come from `local.flow_fields`; any field you do not name matches
anything. Conditions use CloudWatch space-delimited syntax: `="value"` for
equality, `>n` / `<n` for numbers. Fields are positional, so if you change the
flow-log `log_format`, change `flow_fields` to match.

## Network-detection tuning

- **Rejected SSH/RDP** thresholds assume an internet-facing interface sees
  background scanning constantly. Raise them for busy edges; the interesting
  signal is usually an *accept* from a source that was previously rejected.
- **NXDOMAIN / TXT** thresholds are per account per 5 minutes, not per host.
  Some security agents and CDN clients legitimately generate TXT or NXDOMAIN
  bursts; exclude them by adding a `$.srcids.instance != "i-..."` clause.
- **Egress SMB** to internal file servers is normal in Windows estates; add a
  `dstaddr` condition to exclude them.
- **DNS Firewall alerts** fire on every BLOCK or ALERT verdict. If a busy VPC
  produces steady blocks from a known, accepted cause, raise the threshold
  rather than removing the rule, or allow-list the domain if it is benign.
