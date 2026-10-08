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

## Scheduled hunts

### Flow

EventBridge Scheduler starts a Standard Step Functions workflow daily at a fixed
time (flexible window off). Its input lists the scheduled hunts by named-query
ID. A Map state runs them two at a time; for each one:

1. `athena:getNamedQuery` (AWS SDK integration) fetches the saved SQL, so the
   schedule always runs exactly what is saved in the workgroup;
2. `athena:startQueryExecution.sync` runs it and waits;
3. `athena:getQueryResults` reads the header plus up to 5 rows;
4. a Choice state treats more than one row (the header) as findings, and an SNS
   publish sends a JSON alert; a clean hunt ends silently.

Any error in steps 1-3 is caught per hunt and turned into a "FAILED" alert, so
one broken hunt never hides the others. The Map discards per-hunt state
(`ResultPath: null`) to stay far from the 256 KB state-size limit.

### Reporting windows

A saved hunt answers "what in the last 30 days?"; a daily alert must answer
"what is new since yesterday?". The scheduled variant
(`modules/threat-hunting/scheduled_wrapper.sql.tftpl`) wraps the hunt and keeps
rows whose declared time column falls in `[run - 25h, run - 1h)`:

- **Contiguous, non-overlapping.** Daily runs at a fixed UTC time produce windows
  that touch end to end, so each finding is reported once. Pick UTC for the
  schedule: a DST timezone makes some days 23 or 25 hours long.
- **Lagged.** CloudTrail typically delivers within minutes but not instantly.
  The one-hour lag means an event is judged after it has had time to arrive; one
  inside the lag is reported by the next run, not lost.
- **Right-sized scans.** Non-baseline hunts read only the last 2 days of
  partitions. Baseline hunts (new IP, new region, new role path) keep the full
  lookback because "new" needs history, with a 2-day "recent" span so the window
  is fully covered.
- **Full count.** The wrapper adds `findings_total` (a window count) as the
  first column, so an alert showing 5 sample rows still states the total.

Each hunt declares its time column and whether it needs a baseline in its SQL
header. A hunt without them (the access-key pivot) cannot be scheduled: a
precondition stops the plan.

### Trusting silence

A scheduled detector that only speaks when it finds something is
indistinguishable from a broken one. Two alarms close that gap:
`ExecutionsFailed` (the run broke) and a dead man's switch on
`ExecutionsSucceeded` (no successful run on two consecutive UTC days, with
missing data treated as breaching). Two days rather than one avoids a false
alarm on the day you deploy, before the first run.

### Least privilege

The state machine role has the hunter policy (query the workgroup, read-only on
CloudTrail, use the lab key) plus `sns:Publish` on the alert topic. The scheduler
role can only start this state machine. Both trust policies pin
`aws:SourceAccount`.

### Tests

`tests/scheduled/test_state_machine.py` runs the rendered definition through a
small interpreter for the ASL features it uses, with mocks shaped like the real
Athena/SNS responses. It covers findings, a clean run, a failed hunt alongside a
healthy one, and Map output size. Unresolvable JSONPaths fail as they would in
AWS. `tests/hunts/` checks that each scheduled variant finds the same attacks as
its hunt inside the window, nothing two days later, and that across two
consecutive runs every event is reported exactly once. Both suites were
mutation-checked, and the Terraform-rendered scheduled SQL was compared
byte-for-byte with the tests' rendering. Schema validation of the definition:
`npx asl-validator` (see docs/validation.md).

## Network log lake

### Why a second copy

The CloudWatch copies of flow and DNS logs exist for minute-level detection and
are kept 30 days. Hunting wants months of history, cheap scans and joins with
CloudTrail, which is what Parquet in S3 plus Athena gives: columnar files mean a
hunt reading five columns pays for five columns.

### Delivery paths

- **Flow logs:** a second flow log per VPC, destination S3, `file_format =
  parquet`, non-Hive paths
  (`AWSLogs/<account>/vpcflowlogs/<region>/yyyy/MM/dd/`) so the table uses the
  same `dt` projection as CloudTrail. Delivery is vended-log delivery by
  `delivery.logs.amazonaws.com`, allowed by the bucket policy (scoped with
  `aws:SourceAccount` and `aws:SourceArn`) and by a key-policy statement on the
  lab CMK. AWS checks those permissions when the flow log is created, so the lake
  module's `bucket_arn` output depends on the bucket policy.
- **Resolver query logs:** Resolver can deliver to CloudWatch, S3 (JSON) or
  Firehose, one destination per type per VPC, so a second config targets
  Firehose. Firehose deserializes with the OpenX JSON SerDe (case-insensitive, so
  `answers[].Rdata` maps to `rdata`), serializes Parquet with Snappy, and takes
  its schema from the Athena table. Buffering is 64 MiB (the minimum with
  conversion) or 300 s. Prefix
  `route53resolver/AWSLogs/<account>/<region>/!{timestamp:yyyy/MM/dd}/` (UTC
  arrival time), errors under `route53resolver-errors/`.
- **Firehose permissions:** Resolver writes into Firehose through the
  `AWSServiceRoleForLogDelivery` service-linked role, which only works on streams
  tagged `LogDeliveryEnabled=true`. AWS adds that tag when delivery is set up;
  the lab declares it in Terraform so a later apply does not remove it. The
  Firehose role can write only the DNS prefixes, read only the DNS table's schema,
  and use the key only via S3.

### Tables

`vpc_flow_logs` and `resolver_query_logs` live in the hunting database with
`dt` projection from `hunting_projection_start`. The flow table's column types
are AWS's documented Parquet types (`protocol` is `bigint`, ports and
`tcp_flags` are `int`); a mismatch fails at read time, not at create time.

### Source-aware hunts

Each hunt declares `-- requires:` (default `cloudtrail`). The threat-hunting
module saves, and allows scheduling of, only hunts whose sources are deployed,
so disabling the lake removes hunts 15-21 cleanly instead of leaving queries
that fail. Hunt 20 joins flow and DNS with a `LEFT JOIN ... IS NULL` anti-join
(equality on instance plus a 24-hour time bound) rather than a correlated
`EXISTS`, which Trino handles less reliably with range predicates.

### Testing

`tests/hunts/` builds all three tables from schemas parsed out of the modules
(CloudTrail from `threat-hunting/main.tf`, flow and DNS from
`network-log-lake/main.tf`), so a column added to a table without updating the
hunts, or the reverse, fails the suite. Each network hunt has a planted attack
and look-alikes; a mutation round removed each exclusion and join condition in
turn and every removal failed its test. The round also found an exclusion in
hunt 15 (`*.amazon.com`) that no fixture exercised and nothing justified; it
was removed.

## Threat intelligence

### Indicators as code

`intel/indicators/*.csv` is the only place indicators come from. Every change
is reviewed in a pull request and validated by `tests/intel/test_indicators.py`;
Terraform repeats the essential checks (types, enums, dates, internal ranges,
CIDR width, platform apex domains, duplicates) as preconditions, so an invalid
set fails the plan instead of reaching the table. Expiry is mandatory: stale
infrastructure indicators are the classic intel false positive, and an expired
row simply stops matching.

### Publication

The module merges all files, normalises case and whitespace, sorts by
`type|indicator` and writes one quoted CSV to
`s3://<intel-bucket>/indicators/indicators.csv` (versioned, KMS). The Glue table
`threat_indicators` reads it with OpenCSVSerde, all columns as strings. One
sorted object gives two properties: one upload per real change, and no upload
for cosmetic edits. A test proves the Python mirror of this merge produces the
same bytes as Terraform.

### Matching

`modules/threat-hunting/sql/intel_active.sql.tftpl` is a shared CTE, injected
into hunts 22-24 at render time. It drops expired rows and turns every IPv4,
IPv6 or CIDR indicator into a `[lo, hi]` range of canonical address keys
(aligning a misaligned CIDR base), so flow endpoints, DNS answer IPs (A and
AAAA) and CloudTrail source IPs are matched with one `BETWEEN` (see "IPv4 and
IPv6" below). Domain indicators match exact names and subdomains on a dot boundary
(implemented with `reverse()`/`strpos`, which behaves the same in Athena and in
the test engine). These are range and suffix joins against a small table:
fine for a curated list of hundreds or thousands; a feed of millions would
call for a different design (equi-joins on exact IPs, pre-expanded ranges).

### Retro-hunting

The daily run only reports the last 24 hours, so an indicator added today would
never be checked against last week. The intel bucket sends object events to
EventBridge; a rule matching `Object Created` on the indicator object starts the
scheduled-hunts state machine with `retro/...` variants of 22-24: the full hunt
wrapped to add `findings_total`, so alerts work the same way. The rule is
created before the first upload. A test proves a 10-day-old match is found by
the retro variant and ignored by the daily one.

### Recommended schedule

`scheduled_hunts = null` resolves to a recommended set computed from what is
deployed (CloudTrail always; network hunts with the lake; intel hunts with
intel). Every combination of optional layers was checked to recommend only
hunts whose tables exist.

## IPv4 and IPv6

### Why addresses need a canonical key

IPv6 has many spellings for one address (`2001:db8::1`,
`2001:0DB8:0000:0000:0000:0000:0000:0001`, ...), and different AWS log sources
are not guaranteed to agree. String comparison silently fails across them.
Before this change hunt 20 compared DNS answers to flow destinations as
strings, and hunts 18-20 decided "internal" with an IPv4 private-range regex,
so every IPv6 address counted as external (false positives in 18 and 20) and
IPv6 sweeps were invisible to 19.

### Shared SQL (`modules/threat-hunting/sql/`)

- **`ip_key.sql`**: an expression with the placeholder `IP_IN`, instantiated in
  templates with Terraform's `replace()`. It returns 32 lowercase hex digits:
  IPv4 as `::ffff:a.b.c.d`; IPv6 fully expanded (it rebuilds the zero run that
  `::` stands for, then left-pads each group). Fixed width means plain string
  comparison orders keys numerically. Malformed text returns NULL, guarded
  explicitly because `lpad` would otherwise truncate an over-long group into a
  plausible key.
- **`cidr_ranges.sql.tftpl`**: a CTE chain from a `cidr_text` column to `lo`
  and `hi` keys. IPv4 prefixes are offset by 96 into the mapped range; a prefix
  that is not a multiple of 4 masks the boundary hex digit arithmetically.
- **`internal_nets.sql.tftpl`**: private and special ranges of both families
  plus `internal_cidrs`, as ranges.

Only functions with identical behaviour in Athena (Trino) and DuckDB are used,
checked by transpiling each one; the one known difference (`split_part` beyond
the last field: NULL in Trino, `''` in DuckDB) is neutralised by `TRY_CAST`, with
an explicit `nullif` as a guard.

### Internal ranges

`internal_cidrs` is computed in the root module: every IPv4 and IPv6 CIDR block
of each monitored VPC (`cidr_block_associations`,
`ipv6_cidr_block_associations`) plus `extra_internal_cidrs`. Hunts 18 and 20
exclude destinations inside these ranges; hunt 19 requires both ends inside.
Addresses are classified once per distinct address (a range join against a
small table), then filtered with an ordinary `IN`.

### Verification

`tests/hunts/test_ip_keys.py` compares the SQL with Python's `ipaddress` on
random and edge-case input (keys, malformed input, network bounds at every
prefix length, membership). Mutating the SQL (padding, the `::` rules, the IPv4
offset, the partial-nibble mask) fails it. Hunt tests cover IPv6 textual
variants, VPC-internal and ULA addresses, the last address of a /48 and the
first outside it, AAAA answers, and IPv6 sweeps; removing the VPC IPv6 CIDR
from the inputs fails hunts 18-20, which shows that discovery is load-bearing.

## Sigma detection-as-code

### Pipeline

`sigma/rules/*.yml` → `scripts/sigma_convert.py` → `sigma/generated/`
(`metric_filters.json`, `hunts/sigma_*.sql`, `REPORT.md`) → Terraform. The root
module passes the metric filters to the detections module as
`extra_detections` (same metric namespace, alarms and alert topic as the
built-in catalogue) and the hunt directory to the threat-hunting module as an
extra query directory (same rendering, saved queries, scheduling). Generated
files are committed so a plan never depends on Python, and CI's
`--check` step fails if they drift from the rules.

### Why a purpose-built converter

The CloudTrail subset of Sigma is small and well defined, the Athena field
mapping is specific to this lab's table, and, as far as I know, there is no
maintained CloudWatch-metric-filter backend for pySigma. A small converter with
an explicit intermediate representation makes every semantic decision visible
and testable. The trade-off is coverage: unsupported constructs are reported
rather than converted.

### Semantics, target by target

| Concern | Sigma | Athena output | CloudWatch output |
|---------|-------|---------------|-------------------|
| Case | insensitive (unless `\|cased`) | `lower()` both sides | case-sensitive: CloudTrail casing assumed, stated in the report |
| Absent field | condition false | `col IS NOT NULL AND ...` (never NULL) | `$.f = v` is false when absent |
| `not` | true when the field is absent | `NOT` over two-valued leaves | De Morgan to the leaves; `($.f != v \|\| $.f NOT EXISTS \|\| $.f IS NULL)` |
| Wildcards | `*`, `?`, `\` escapes | `LIKE ... ESCAPE '!'` (no backslashes: dialects disagree on them) | `*` at value edges only |
| `null` / exists | absent or null | `IS NULL` / `IS NOT NULL` | `NOT EXISTS \|\| IS NULL`; "exists" not expressible |
| `\|cidr` | IP in network | shared `ip_key` ranges, `coalesce(..., FALSE)` | not expressible |
| `\|re` | regex search | `regexp_like` (`(?i)` for `\|i`) | not converted (CloudWatch regex is a restricted dialect) |
| Length | - | - | patterns over 1024 characters skipped |

### Field mapping

Sigma uses raw CloudTrail field names (`userIdentity.type`,
`requestParameters.policyArn`). For Athena, top-level fields map to the
table's lower-case columns, `userIdentity`/`tlsDetails`/`addendum` paths to
struct fields (validated against the Glue type; a test fails if the converter's
map and the table drift apart), and `requestParameters`/`responseElements`/
`additionalEventData` paths to `json_extract_scalar`. Array fields
(`resources`) are refused for both targets: a CloudWatch selector on an array
never matches, so converting it would be a silent false negative.

### Testing

Three implementations per rule: a Python reference interpreter of Sigma over
raw CloudTrail JSON, the generated SQL in DuckDB, and an independent parser and
evaluator of the generated CloudWatch pattern text following the documented
semantics (case-sensitive, edge wildcards, `IS NULL`/`NOT EXISTS`, no match on
objects or arrays). Each lab rule has hand-written expectations; fixture rules
cover every supported construct and every refusal; randomised events (absent,
null, matching, near-miss, wildcard-confusing and case-flipped values) must give
identical results, except case-flipped events for CloudWatch, which a dedicated
test asserts differ. Because all three share the parsed rule, parser bugs are
caught by the hand-written expectations rather than by the differential
comparison. Ten planted converter bugs were all caught. Limits: CloudWatch is
modelled from its documentation, not executed.

### Logs Insights: the second real-time path

`scripts/sigma_convert.py` has a third backend that writes each rule as a
CloudWatch Logs Insights filter. Every comparison and function it uses returns
a boolean (documented), so `not` needs none of the NULL guarding SQL needs;
`isIpInSubnet` returns false for a value that is not an IP, which is exactly the
case that broke the Athena CIDR hunt before. String conditions become anchored
RE2 regexes with `(?i)` unless `|cased`, every non-alphanumeric character
escaped (so `.`, `_` and `%` are literal), and each is guarded with
`ispresent()`.

Two behaviours are not documented: how a JSON boolean appears as an
auto-discovered field, and whether a JSON `null` counts as present. Boolean
conditions are emitted as `(f = 1 or f = "true")` so either representation
works; `null` is assumed to count as absent. The conformance tier ingests probe
events and fails, naming the assumption, if either is wrong; offline tests run
that check against a fake service that misbehaves in each way to prove it would.

`modules/sigma-insights` deploys each rule as a saved query
(`aws_cloudwatch_query_definition`) and a log alarm
(`awscc_cloudwatch_log_alarm`: `count(*)` of the query, `>= 1` in 1 of 1 runs,
every 5 minutes over a 15-minute lookback so CloudTrail's delivery delay to
CloudWatch Logs is tolerated; an event can therefore be counted by up to three
consecutive runs). The scheduled-query role follows AWS's documented policy:
trusted by `logs.amazonaws.com`, limited to Logs Insights calls on the CloudTrail
log group, plus `kms:Decrypt` via CloudWatch Logs for the encrypted group.

| | Metric filter | Logs Insights log alarm | Athena hunt |
|-|---------------|-------------------------|-------------|
| Latency | event delivery + up to 5 min | event delivery + up to 5 min | CloudTrail S3 delivery (5-15 min) + schedule |
| Semantics | case-sensitive; no exists, regex or CIDR | Sigma's (case-insensitive, `ispresent`, RE2, `isIpInSubnet`) | Sigma's |
| History | from creation onwards | lookback window | full retention in S3 |
| Provider | `hashicorp/aws` | `hashicorp/awscc` | `hashicorp/aws` |

## Multi-account

`org/management` and `org/security-admin` apply the delegated-administrator
pattern for GuardDuty and Security Hub across an organization: GuardDuty
delegated and configured in every region, Security Hub central configuration
from the home region, findings from every account and region alerting from the
administrator account. Member accounts running the lab set
`organization_managed_threat_detection`. See [multi-account.md](multi-account.md).
