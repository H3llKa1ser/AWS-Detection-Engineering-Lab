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
