# Changelog

## 0.6.0: Scheduled hunts

### Added
- `modules/scheduled-hunts`: EventBridge Scheduler (daily, fixed UTC time) ->
  Step Functions Standard workflow (`statemachine.asl.json.tftpl`) using native
  Athena and SNS integrations: fetch each saved query, run it, alert only on
  findings or failures. No Lambda code.
- Scheduled variants of hunts (`scheduled/...` named queries) built from
  `scheduled_wrapper.sql.tftpl`: report only rows from the 24h window ending one
  hour before the run, so each finding is reported once; `findings_total`
  carries the full count. Hunts declare `schedule-time-column` and
  `schedule-baseline` in their SQL headers.
- JSON alerts with ATT&CK mapping, total, sample rows, execution ID and results
  path; per-hunt failure alerts; run-failure alarm and a two-day dead man's
  switch on successful runs.
- `tests/scheduled/test_state_machine.py` (ASL data-flow interpreter with
  API-shaped mocks) and scheduled-variant tests in `tests/hunts/` (window
  behaviour, exactly-once reporting across consecutive runs).
- Root variables `enable_scheduled_hunts`, `scheduled_hunts` (10 by default),
  `hunt_schedule_hour`, `hunt_schedule_timezone`; outputs
  `run_scheduled_hunts_now` and `scheduled_hunts`.

### Changed
- Hunt 10 also returns `last_read` (a timestamp) so it can be scheduled.
- Hunter IAM policy also allows `athena:GetDataCatalog` on the default catalog
  (required by the Step Functions Athena integration).
- README cost section restructured into per-layer notes.

## 0.5.0: Threat hunting with Athena

### Added
- `modules/threat-hunting`: Glue database and CloudTrail table over the existing
  CloudTrail bucket (AWS's JsonSerDe schema, read in place), partition
  projection on region and day, an enforced Athena engine v3 workgroup with
  encrypted, expiring results and a per-query scan cap.
- 14 saved queries mapped to MITRE ATT&CK: new console source, spray-then-success,
  permission probing, enumeration bursts, IAM persistence, sensor tampering,
  new-region activity, data shared out, compute hijacking, secret harvesting,
  replayed instance credentials, root activity, new role-assumption paths, and
  an access-key investigation timeline.
- Hunter IAM policy (unattached): query-only, read-only on CloudTrail.
- `tests/hunts/`: behavioural tests for every query (planted attack vs benign
  look-alikes) in DuckDB via sqlglot, schema parsed from the module,
  mutation-checked. Runs without AWS.
- Root variables `enable_threat_hunting`, `hunting_projection_start`,
  `hunting_lookback_days`, `hunting_recent_days`, `hunting_bytes_scanned_cutoff`.

## 0.4.0: DNS Firewall Advanced, AWS provider 6.x

### Added
- DNS Firewall Advanced rules (priorities 400+): DGA, dictionary DGA and DNS
  tunnelling detectors with per-rule BLOCK/ALERT and LOW/MEDIUM/HIGH confidence.
  Default: all three BLOCK at MEDIUM. Plan-time validation of protection names
  (the provider does not validate them).
- Per-protection EventBridge rules on DNS Firewall's `DNS Firewall Block` /
  `DNS Firewall Alert` events, raw events kept in
  `/aws/events/<prefix>-dns-firewall-advanced`, and alarms on each rule's
  `MatchedEvents` metric to SNS, identifying which detector fired.
- Traffic generator: DGA-shaped names under real TLDs and a dictionary-DGA burst.

### Changed
- **`hashicorp/aws` ~> 5.0 -> ~> 6.0.** Advanced rules need 6.x: in 5.x a
  firewall rule requires a domain list and has no threat-protection settings.
- GuardDuty protection plans moved from the deprecated `datasources` block to
  `aws_guardduty_detector_feature` (S3 data events, EBS malware protection).
- `data.aws_region.current.name` -> `.region` (deprecated in 6.x).
- Lab CMK key policy also covers `/aws/events/<prefix>-*` log groups.

### Upgrading an existing deployment from 0.3.x
1. `terraform init -upgrade` to fetch provider 6.x.
2. `terraform plan`: expect two new `aws_guardduty_detector_feature` resources
   (they take over settings the detector already has), the Advanced rules,
   EventBridge rules and alarms, and an in-place KMS key policy update.
3. Review, then apply.

## 0.3.0: DNS Firewall, plus corrections

### Added
- `modules/dns-firewall`: Route 53 Resolver DNS Firewall rule group with the AWS
  managed malware, botnet C2 and aggregate threat lists, a custom block list
  (defaults to public cryptomining pools) and an allow list for false
  positives. Per-list BLOCK/ALERT, NODATA/NXDOMAIN/OVERRIDE responses,
  explicit fail-closed config, enforced on the lab VPC by default.
- Managed-list ID lookup by name via the AWS CLI (`external` data source), with
  provider-side verification that each ID is the AWS-managed list it claims.
- Detections `dns_firewall_block` and `dns_firewall_alert` (26 total).
- Traffic generator queries AWS's published test domains for the managed lists.

### Fixed
- **CIS control numbers.** Detections were labelled CIS 3.1-3.15 (the v1.2
  numbering, which has no 3.15). The lab subscribes Security Hub to CIS v1.4.0,
  where these are 4.1-4.15. Labels in the catalogue and README now match.
- **AWS Config delivery.** The recorder runs under a custom IAM role, which
  delivers to S3 as itself, but the role had only `AWS_ConfigRole` (no S3
  access). Added a scoped `s3:PutObject` / `s3:GetBucketAcl` role policy.
- **Traffic generator security group.** Its "DNS-only" egress rule was a no-op:
  security groups do not filter traffic to the Amazon DNS server. The group now
  has no rules at all, which is what the instance actually needs.
- **Response Lambda reporting.** `RevokeSecurityGroupIngress` can succeed while
  listing the rule as unknown (nothing removed); the Lambda counted that as a
  revocation. It now checks `UnknownIpPermissions` and inspects every ENI, not
  just the first.
- **Validation doc.** The IAM test command used an empty policy statement,
  which IAM rejects as malformed; replaced with a valid policy and cleanup step.

## 0.2.0: Network telemetry
- VPC Flow Logs (custom v5 format) and Route 53 Resolver query logging to
  CloudWatch Logs, an isolated lab VPC, nine network/DNS detections, and an
  opt-in DNS traffic generator.

## 0.1.0: Initial lab
- CloudTrail, AWS Config, GuardDuty, Security Hub, 15 CloudTrail detections,
  SNS/EventBridge alerting, opt-in Lambda response.
