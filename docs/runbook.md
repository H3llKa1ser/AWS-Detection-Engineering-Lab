# Runbook

Short triage notes for the alerts this lab produces. In production these would
live next to each detection and link to your ticketing system.

## A metric-filter alarm fired (e.g. "security group changes")

1. Open the alarm in CloudWatch → note the time window.
2. Pivot to CloudTrail (console or Logs Insights) for the same window and the
   event name(s) in the detection pattern.
3. Identify the principal (`userIdentity`), source IP and whether the change was
   expected (change ticket? known automation?).
4. If unexpected: disable the principal's credentials, revert the change, open an
   incident.

### Logs Insights starter query

```
fields @timestamp, userIdentity.arn, eventName, sourceIPAddress, errorCode
| filter eventName like /AuthorizeSecurityGroupIngress|RevokeSecurityGroupIngress/
| sort @timestamp desc
| limit 50
```

## A GuardDuty finding fired

1. Read the finding type and severity in the SNS message.
2. Open the finding in GuardDuty for the full context (actor, resource, TTP).
3. Map the finding type to its [GuardDuty finding docs](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html).
4. Contain the affected resource (isolate instance / rotate credentials) before
   eradication.

## Root account usage alarm

Treat as high priority. Root should almost never be used interactively. Confirm
with the account owner immediately; if unexplained, rotate the root password,
re-check root MFA, and review all root activity in CloudTrail.

## Response automation revoked a security-group rule

The Lambda only removes `0.0.0.0/0` ingress rules named in a port-probe finding.
Verify the revoked rule was not legitimately needed; if it was, re-add it scoped
to a specific CIDR rather than the world.

## Network and DNS detections

All flow and DNS alarms are volume- or indicator-based. The alarm tells you
*something* matched; the logs tell you *who*. Start every triage with a Logs
Insights query over the right log group and window.

### Rejected SSH / RDP bursts, rejected-flow spike

Usually internet background noise hitting an exposed interface. What matters is
whether anything was *accepted* from the same sources.

```
# log group: /<prefix>/vpc-flow-logs  (custom format, so parse it)
parse @message "* * * * * * * * * * * * * * * * * * * * * *" as version, account_id, interface_id, srcaddr, dstaddr, srcport, dstport, protocol, packets, bytes, start, end, action, log_status, vpc_id, subnet_id, instance_id, tcp_flags, type, pkt_srcaddr, pkt_dstaddr, flow_direction
| filter action = "REJECT" and flow_direction = "ingress"
| stats count(*) as rejects, count_distinct(dstport) as ports by srcaddr, interface_id
| sort rejects desc
| limit 25
```

Then re-run with `action = "ACCEPT"` and `srcaddr` set to the top talkers. Many
distinct ports from one source is a scan; many hits on one port is brute force.
If there are accepts, treat it as possible initial access.

### Accepted outbound SMB / large egress flow

Identify the instance (`instance_id`) and destination (`dstaddr`). Internal SMB
between known file servers is normal; tune those out by adding a `dstaddr`
condition to the detection. SMB or bulk transfer to the internet is not: isolate
the instance (swap to a quarantine security group) and preserve its EBS volume
before investigating.

### NXDOMAIN spike / TXT query spike

```
# log group: /<prefix>/route53-resolver-queries
filter rcode = "NXDOMAIN"
| stats count(*) as hits by srcids.instance, query_type
| sort hits desc
```

One instance producing many random-looking names is the DGA pattern. Many TXT
queries with long, high-entropy labels under one parent domain is the tunnelling
pattern; look at that parent domain's registration age and reputation. Swap
`NXDOMAIN` for `query_type = "TXT"` to pivot.

### Cryptomining pool lookup

Expect GuardDuty `CryptoCurrency:EC2/BitcoinTool.B!DNS` alongside it. Mining on
cloud compute almost always means compromised credentials or a compromised
workload: find how the instance was launched or modified (CloudTrail
`RunInstances` / `ModifyInstanceAttribute` for that instance id), stop it,
snapshot it, and rotate the credentials involved.

### .onion lookup

A `.onion` name cannot resolve through normal DNS, so the lookup itself is the
signal: something on the host thinks it can reach Tor. Identify the process on
the instance and check for a local Tor client or proxy configuration.

## DNS Firewall block / alert

A block means the lookup failed, not that the host is clean. Something on that
instance asked for a known-bad or denylisted domain.

```
# log group: /<prefix>/route53-resolver-queries
filter firewall_rule_action = "BLOCK" or firewall_rule_action = "ALERT"
| stats count(*) as hits, earliest(query_timestamp) as first_seen by srcids.instance, query_name, firewall_domain_list_id, firewall_rule_action
| sort hits desc
```

1. Map `firewall_domain_list_id` to a list name with
   `terraform output dns_firewall_managed_list_ids` (or it is your custom
   blocklist). Malware or botnet C2 lists: treat the instance as compromised.
2. Check the same instance's other DNS and flow activity for the same window:
   did it reach anything by IP after the name lookup failed?
3. Find what launched or last changed the instance (CloudTrail `RunInstances`,
   `ModifyInstanceAttribute`, SSM `SendCommand`).
4. Contain (quarantine security group), snapshot the volume, then investigate.

**ALERT** matches come from lists running in evaluation mode. Review a few days
of them; if they are all real threats or all noise you can explain, switch the
list to BLOCK, adding any explained noise to the allow list first.

### False positive

AWS's documented approach: confirm in the query log which rule group and list
blocked the domain, then allow it with a higher-priority rule rather than
weakening the block rule. Here that means adding the apex domain to
`dns_firewall_allow_domains` (priority 100, ahead of every block rule) and
applying. Record why in the commit message.

## DNS Firewall Advanced alarm (DGA / dictionary DGA / tunnelling)

The alarm name tells you the detector. Each underlying event is a newly flagged
name. Raw events are in `/aws/events/<prefix>-dns-firewall-advanced`; their
field names contain hyphens, so Logs Insights needs backticks:

```
fields @timestamp, `detail.firewall-protection` as protection,
       `detail.firewall-rule-action` as action, `detail.query-name` as name,
       `detail.query-type` as qtype, `detail.resources.0.instance-details.id` as instance
| sort @timestamp desc
| limit 100
```

- **DGA / dictionary DGA.** Malware cycling through generated domains to find its
  command-and-control server. One instance producing many flagged names is a
  strong compromise signal even if every lookup was blocked: the malware is
  running. Contain the instance, then look for how it got there.
- **DNS tunnelling.** Data or C2 carried in DNS labels, usually many unique
  subdomains under one parent. Group the flagged names by their parent domain to
  find the tunnel endpoint, then check how long the host has been talking to it
  in the Resolver query logs (`query_name like /<parent>/`), because anything
  before the block may have left.
- **Rule in ALERT mode.** The queries were answered. Treat as an incident if the
  pattern is real; if it is a known benign client, allow-list its domain.

To pivot from a flagged name to every query that host made, take `srcids.instance`
or `srcaddr` from the matching record in the Resolver query logs.

## Threat hunting (Athena)

### Running hunts

Athena console, workgroup `<prefix>-threat-hunting`, **Saved queries**. Each
hunt's description gives its purpose and ATT&CK mapping. A suggested weekly
rotation: 06 (sensor tampering) and 05 (IAM persistence) every time, since they
are cheap and high-signal; the rest on a rotation or when an alert points at
them.

### From alert to hunt to investigation

1. **Alert** (metric filter, GuardDuty, DNS Firewall) names an identity, key, IP
   or instance.
2. **Hunt** for related behaviour from the same actor: 03 and 04 (did they
   enumerate?), 05 (did they persist?), 06 (did they blind the sensors?), 07
   (did they go to another region?), 08 (did data leave?).
3. **Investigate** with 14: replace the placeholder key and get the full ordered
   timeline. For role sessions, use the `ASIA...` key from the event.
4. **Scope** by widening the `dt` filter if the earliest activity sits at the
   edge of the window.

### Reading results

- An empty result is an answer: record that the hunt ran clean.
- Baseline hunts (01, 07, 13) need history. In the first days after deployment
  everything is "new"; their results become meaningful once the baseline window
  holds normal activity.
- Hunt 06 also shows your own Terraform changes. Confirm the actor is your
  deployment identity and matches a change you made.
- Tune by editing the `.sql` file (thresholds sit in the `HAVING` clause), then
  update its test with the case that motivated the change, then apply.

### Cost guard

If a query is cancelled for exceeding the scan cap, narrow the `dt` range rather
than raising the cap. `hunting_bytes_scanned_cutoff` exists to stop accidents.

### Scheduled hunt alerts

Subject `[<prefix>] hunt findings: <hunt>`. The message is JSON:

| Field | Use |
|-------|-----|
| `hunt`, `title`, `attack` | Which hunt, and the technique it looks for |
| `findings_total` | Rows in this 24h window (the sample may show fewer) |
| `sample_rows_including_header` | Row 0 holds column names; rows 1-5 are findings |
| `results_csv` | S3 path of the complete result set |
| `query_execution_id` | `aws athena get-query-results --query-execution-id <id>` |

Triage as for the hunt itself (sections above). The window covers the 24h ending
one hour before the run, so a finding is reported once; if it continues, the next
day's run reports the new activity.

**`hunt FAILED: <hunt>`**: that hunt did not run today, and is blind until fixed.
The `cause` usually says why: scan cap exceeded (narrow the hunt or raise
`hunting_bytes_scanned_cutoff`), permissions, or a query error after an edit.
Fix, then run `terraform output -raw run_scheduled_hunts_now` and execute it.

**`scheduled_hunts_execution_failed`**: the run itself broke, so no hunt
reported. Open the execution in the Step Functions console for the failed step.

**`scheduled_hunts_not_running`** (dead man's switch): no successful run on two
consecutive days. Check the schedule is `ENABLED`
(`aws scheduler get-schedule --name <prefix>-daily-hunts`), the scheduler role
still exists, and the execution history. Silence from the hunts means nothing
until this alarm is OK again.

### Changing what runs

Add or remove names in `scheduled_hunts` and apply. Before scheduling 04, 10 or
11, run them by hand for a week and tune the thresholds in their SQL so a normal
day is empty.

## Network hunts (flow and DNS)

**15 DNS beaconing.** A low `jitter` with a steady `avg_interval_seconds` means
software, not a person. Look up the domain: unknown or newly registered, plus an
instance with no reason to poll it, is a likely implant. Run 21 on the instance.
Benign pollers (agents, update checks) go into the hunt's exclusion regex.

**16 New, rare domain.** One instance, never-before-seen domain. Check
registration age and reputation, then what the instance did right after (21).
Common benign cause: a developer testing a new SaaS from one box.

**17 DNS tunnelling shape.** Group by `parent_domain`. Long random first labels
at volume mean data in DNS. Check DNS Firewall verdicts for the same names and
how long it has been going on (widen `dt`). Treat as exfiltration until
disproved.

**18 New external transfer.** Large upload to a destination the instance never
used. Identify what the destination is (IP owner, ports). Backups and new
integrations are common; unexplained transfers from data-holding instances are
not.

**19 Internal sweep.** Many internal hosts or ports from one source in an hour.
Many `rejected` means it was probing; check what was accepted, and whether the
source is a known scanner or monitoring host.

**20 Egress without DNS.** The instance connected to public IPs it never
resolved. Hard-coded IPs are a classic C2 trait, but also check for instances
using their own resolver (which bypasses Resolver logs and DNS Firewall, itself
a finding) and for software that connects by IP by design.

**21 Investigate an instance.** Replace the placeholder instance ID. The
`cloudtrail: about instance` rows show who launched or changed it; `by instance`
rows show what its role credentials did.

### Lake health

If a network hunt returns nothing for days on a busy VPC, check delivery before
trusting the silence (see "Network log lake" in validation.md): Firehose
conversion errors, the `LogDeliveryEnabled` tag, and the S3 flow log's
delivery status.

## Threat-intel hunts

**22 Intel: flows.** Start with `accepted` egress rows: something inside talked
to known-bad infrastructure. An ingress row next to an egress row for the same
IP is usually reply traffic. Check the indicator's `confidence` and
`description`, then run 21 on the instance. Rejected ingress from a bad IP is
mostly noise unless something was also accepted.

**23 Intel: DNS.** `matched_on = domain` means the name itself is known-bad;
`answer <ip>` means a different name resolved to known-bad infrastructure (shared
hosting, or a fresh domain on old C2). `dns_firewall` shows whether it was
already blocked: a block stopped the lookup, not the malware that made it.

**24 Intel: CloudTrail.** Valid credentials used from known-bad infrastructure.
Treat as compromise: deactivate the access key or revoke the session, rotate,
then investigate with 14. Count `succeeded`, not just calls.

**retro/<hunt> alerts** come from a change to the indicator set and cover the
full lookback. They may include activity from weeks ago: scope the incident to
that whole period.

### Curating indicators

1. Add rows to a file in `intel/indicators/` (or run `scripts/import_feodo.py`).
2. `python3 tests/intel/test_indicators.py` and fix anything it reports.
3. Open a pull request with the source and reasoning; merge; `terraform apply`.
   The retro-hunt starts on its own.
4. Monthly, run hunt 25 and prune or re-verify what is expiring or expired.

**False positive?** Lower the indicator's confidence, shorten its expiry, or
remove it, with the reason in the pull request. Do not keep a known-false
indicator around to "watch" it: that is what ALERT-mode DNS Firewall lists are
for.

## IPv6 notes

- Hunts show addresses as the logs wrote them; matching ignores notation, so a
  `2001:DB8:0:0:0:0:0:1` in a result row can match the indicator `2001:db8::1`.
- If hunts 18 or 20 report a destination you know is internal (a peered VPC, a
  second VPC IPv6 block in another account, on-premises), add the range to
  `extra_internal_cidrs` and apply; `terraform output internal_cidrs` shows what
  is currently treated as internal.
