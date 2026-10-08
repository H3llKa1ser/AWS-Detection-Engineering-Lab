# Changelog

## 0.13.0: Multi-account delegated administrator

### Added
- `org/management` and `modules/org-delegation`: GuardDuty trusted access (one
  idempotent CLI call, since GuardDuty needs it before an API-designated admin
  and `hashicorp/aws` could only do it by owning the whole organization),
  GuardDuty delegated administrator in every region, Security Hub enabled in the
  management account and delegated in the home region. Both delegations have
  `prevent_destroy`.
- `org/security-admin` and `modules/org-security-admin`: GuardDuty detector,
  organization configuration (auto-enable `ALL`) and protection plans in every
  region; Security Hub central configuration (finding aggregator, `CENTRAL`,
  configuration policy with FSBP and CIS 1.4.0, associations); alerting for
  every account and region through the existing alerting module. Uses the
  `hashicorp/aws` 6.x per-resource `region` argument instead of provider aliases.
- Variable `organization_managed_threat_detection` for member accounts running
  the lab.
- `scripts/verify_org.py`: checks a real organization after apply.
- Tests: `tests/org/test_org_plans.py` (offline plans of both roots, assertions
  on resources, ordering, validation and `prevent_destroy`; seven planted
  mistakes caught) and `tests/org/test_verify_org.py`. CI validates every root.
- `docs/multi-account.md`.

### Not yet done
- Not applied to a real organization by the author.

## 0.12.0: Sigma to CloudWatch Logs Insights (second real-time path)

### Added
- Third backend in `scripts/sigma_convert.py`: Logs Insights filters with Sigma's
  semantics (case-insensitive anchored RE2 regexes, `ispresent()`,
  `isIpInSubnet()` for IPv4 and IPv6). All nine lab rules convert, including the
  CIDR rule metric filters cannot express. `sigma/generated/insights_queries.json`;
  the report gains a column.
- `modules/sigma-insights`: per rule, a saved query and a CloudWatch log alarm
  (AWS, November 2025) via `hashicorp/awscc`, since `hashicorp/aws` has no
  resource for it yet. Variables `enable_sigma_log_alarms`,
  `sigma_log_alarm_schedule_minutes`, `sigma_log_alarm_lookback_minutes`.
- Tests: a model of Logs Insights in `tests/sigma/test_sigma.py` that must agree
  with the reference on every event, case-flipped ones included; mutation-checked.
  Live conformance runs every Sigma query on real Logs Insights and probes
  JSON boolean/null behaviour; a fake service in the offline harness tests
  proves that check fails when the probes would. The e2e tier expects the SSM
  trigger's log alarm; the janitor sweeps conformance log groups.

### Fixed
- **Minimum Terraform version.** Since 0.3.0 (DNS Firewall) the configuration has used
  validation rules that compare variables, which need Terraform 1.9, while
  declaring `>= 1.5`; on 1.5-1.8 it failed with "Invalid reference in variable
  validation". `required_version` is now `>= 1.9.0` (1.8 now gets a clear
  version error) and the README says so.
- Sigma tests: a `.` that acted as a regex wildcard went undetected; the
  generator now produces dot-substituted near-misses, and a hand-written case
  covers it.

## 0.11.0: Live tiers in a sandbox account

### Added
- `.github/workflows/live.yml`: on demand and weekly, behind the `sandbox`
  environment, after the offline suite passes.
  - **Conformance** (`tests/live/test_conformance.py`): all 26 built-in metric
    filters against hand-written samples, and every Sigma metric filter against
    the CloudWatch model, through the real `TestMetricFilter` API; the IP key
    and CIDR SQL through real Athena against Python's `ipaddress`.
  - **End to end** (`tests/live/test_e2e.py`): apply with `ci/e2e.tfvars` and a
    per-run prefix and state; every saved query executes; retro and scheduled
    hunts complete without FAILED alerts; safe triggers raise six alarms via
    SNS; hunts 05, 23 and the Sigma SSM hunt find the triggered activity; the
    Sigma hunts match the reference implementation on synthetic CloudTrail
    files; destroy always.
- `.github/workflows/live-janitor.yml` and `tests/live/janitor.py`: destroy
  stacks whose state outlived its run, sweep test activity outside Terraform.
- `ci/bootstrap/`: GitHub OIDC provider, CI role trusted only by this
  repository's `sandbox` environment, guardrail denies, versioned state bucket,
  CI Athena workgroup, monthly budget alert.
- `ci/render-catalogue/`: renders the detection catalogue's patterns with a
  Terraform plan that needs no AWS access.
- `tests/live/catalogue_samples.py`: positive and negative samples for all 26
  built-in detections, with `PROBE` cases for undocumented CloudWatch behaviour.
- `tests/live/test_harness_offline.py` (in the offline CI suite): query
  builders in DuckDB, catalogue samples vs the model, botocore validation of
  every API call, helpers, and the workflows' safety properties.
- `docs/live-testing.md`. Output `scheduled_hunts_state_machine_arn`.

### Changed
- The CloudWatch model in `tests/sigma/test_sigma.py` accepts unquoted values
  (as in AWS's CIS patterns); the Sigma expectation tables are module-level so
  the live tier reuses them.
- `tests.yml` is reusable (`workflow_call`) as the live gate and also runs the
  live harness's offline tests.

### Not yet done
- The live tiers have not been run against AWS by the author.

## 0.10.0: Sigma detection-as-code, CI

### Added
- `scripts/sigma_convert.py`: converts CloudTrail Sigma rules to CloudWatch
  metric filters and Athena hunts, keeping Sigma semantics (case-insensitive,
  absent-field rules, negation) and skipping, with reasons, what a target
  cannot express. `--check` for CI.
- `sigma/rules/aws/`: nine lab rules (GuardDuty disabled, S3 Block Public Access
  removed, root access key, EC2 user data modified, unauthenticated Lambda URL,
  SSM by a person, Secrets Manager policy, leaving the organization, console
  sign-in outside known ranges). `sigma/generated/`: metric filters, hunts and
  `REPORT.md`. `sigma/README.md`.
- Detection catalogue accepts `extra_detections`; threat-hunting module accepts
  `extra_query_dirs`. Root variables `enable_sigma`, `sigma_generated_dir`;
  output `sigma`. Sigma hunts can be scheduled (`sigma_<rule>`).
- `tests/sigma/test_sigma.py`: Python reference vs generated SQL (DuckDB) vs a
  model of documented CloudWatch semantics; hand-written expectations,
  fixtures for every construct and refusal, randomised differential testing.
- `.github/workflows/tests.yml`: runs every offline suite, the Sigma freshness
  check, ASL validation, and Terraform fmt/validate. Earlier docs referred to
  "CI"; this is it.

### Found by the new tests
- A negated `|cidr` produced SQL whose comparison was NULL for non-IP source
  addresses, which silently dropped those events. Every Athena leaf is now
  two-valued.

## 0.9.0: IPv6

### Fixed
- **Hunts 18-20 mishandled IPv6.** "Internal" was an IPv4 private-range regex,
  so every IPv6 address counted as external: VPC-internal and ULA traffic
  appeared as external transfers (18) and unresolved egress (20), and IPv6
  sweeps were invisible (19). Hunt 20 also compared DNS answers to flow
  destinations as strings, which fails across IPv6 notations.

### Added
- Shared SQL in `modules/threat-hunting/sql/`: canonical 32-hex address keys
  for IPv4 and IPv6 (`ip_key.sql`), CIDR to key ranges at any prefix length
  (`cidr_ranges`), and internal ranges (`internal_nets`).
- Internal ranges = private/special ranges of both families + every IPv4 and
  IPv6 CIDR block of the monitored VPCs (discovered) + `extra_internal_cidrs`.
- Lab VPC is dual-stack (`lab_vpc_ipv6`, Amazon-provided /56).
- Indicators: `ipv6` type and IPv6 CIDRs (/32 or narrower), IPv6 internal and
  special ranges rejected, canonical RFC 5952 notation required in CI;
  Terraform plan-time checks for the same essentials. IPv6 canaries in
  `lab-canaries.csv`; the Feodo importer accepts IPv6.
- `tests/hunts/test_ip_keys.py`: property tests of the SQL against Python's
  `ipaddress`. IPv6 cases in hunt tests 18-20 and 22-24.
- Outputs `internal_cidrs`; variables `lab_vpc_ipv6`, `extra_internal_cidrs`.

### Changed
- Hunts 22-24 match on canonical key ranges instead of IPv4 integer ranges
  (same results for IPv4; all IPv4 tests unchanged and passing).
- `intel_active.sql.tftpl` moved to `modules/threat-hunting/sql/`.

## 0.8.0: Threat intelligence and retro-hunting

### Added
- `intel/indicators/*.csv`: curated indicators as code (indicator, type,
  source, confidence, added, expires, description, reference) with
  `intel/README.md` rules; `lab-canaries.csv` seed (documentation ranges and a
  `.invalid` canary domain only, no real indicators).
- `modules/threat-intel`: plan-time validation, deterministic merge into one
  versioned, KMS-encrypted S3 object, `threat_indicators` Athena table, S3
  events to EventBridge.
- Hunts 22-25: intel matches in flows, DNS (names, subdomains and resolved
  IPs) and CloudTrail source IPs; intel inventory report. Shared
  `intel_active` CTE: expiry filter, IPv4/CIDR as integer ranges.
- Retro-hunting: `retro/...` full-lookback variants of 22-24, run by the
  scheduled-hunts state machine whenever the indicator object changes.
- `scripts/import_feodo.py`: Feodo Tracker botnet C2 importer with short expiry.
- `tests/intel/`: curation rules, merge mirror (byte-identical to Terraform),
  importer tests. Hunt tests for 22-25, retro coverage, and the curated canary
  matched end to end. Mutation-checked range, expiry and domain-boundary logic.
- Traffic generator resolves the intel canary every cycle.
- Root variables `enable_threat_intel`, `intel_indicator_dir`,
  `retro_hunt_on_intel_change`; output `threat_intel`.

### Changed
- `scheduled_hunts` now defaults to `null`: a recommended set computed from the
  deployed layers (10-16 hunts), instead of a fixed CloudTrail-only list. An
  explicit list still overrides it. Validated for every on/off combination.
- Hunter policy reads the intel prefix (including object versions).

## 0.7.0: Network log lake (flow and DNS in Parquet) and network hunts

### Added
- `modules/network-log-lake`: KMS-encrypted S3 bucket for network logs; Athena
  tables `vpc_flow_logs` and `resolver_query_logs` with `dt` partition
  projection (same scheme as CloudTrail); Firehose stream converting Resolver
  JSON to Parquet using the Athena table as its schema, with error output and
  CloudWatch error logging.
- Second, S3-destined flow log per VPC delivering native Parquet with the
  AWS-service and traffic-path fields; second Resolver query-log config
  targeting Firehose.
- Hunts 15-21: DNS beaconing, new rare domains, DNS tunnelling shape, new
  external transfers, internal sweeps, egress without DNS (flow ⨝ DNS), and a
  cross-source instance timeline. 15-20 are schedulable.
- `-- requires:` header: hunts are saved and schedulable only when their tables
  exist.
- Hunter policy: read-only access to the network log prefixes.
- Tests: three-table harness with schemas parsed from both modules; tests and
  mutation checks for the seven new hunts.
- Root variables `enable_network_log_lake`, `network_lake_retention_days`;
  output `network_log_lake`.

### Changed
- Lab CMK key policy allows vended log delivery (`delivery.logs.amazonaws.com`,
  scoped to this account's log sources) to write SSE-KMS objects.
- Validation doc: test-count expectations replaced with "all passed" (the
  hard-coded counts had already gone stale).

### Note
- AWS allows 2 flow logs per VPC; the lake uses the second on each monitored VPC.

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
