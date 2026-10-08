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
