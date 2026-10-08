# Sigma rules

Detections written once in [Sigma](https://sigmahq.io/) and converted by
`scripts/sigma_convert.py` into this lab's three targets:

- **CloudWatch Logs metric filters** over the CloudTrail log group, added to the
  detection catalogue with alarms to the alert topic (real time, minutes);
- **CloudWatch Logs Insights log alarms** over the same log group: CloudWatch
  runs the rule's Logs Insights query every 5 minutes and alarms on a match
  (`<prefix>-insights-sigma_<rule>`), plus a saved query per rule. This is the
  second real-time path, and the one with Sigma's exact semantics;
- **Athena hunts** over the CloudTrail table, saved in the hunting workgroup and
  schedulable like any other hunt (`sigma_<rule file name>`).

A rule is converted to a target only if that target can express it with the same
meaning. Anything else is skipped for that target, with the reason, in
[generated/REPORT.md](generated/REPORT.md). Nothing is approximated.

## Workflow

1. Write or copy a rule into `sigma/rules/` (`logsource: {product: aws, service: cloudtrail}`).
2. `python3 scripts/sigma_convert.py` and read the report line for your rule.
3. `python3 tests/sigma/test_sigma.py`. For a new lab rule, add hand-written
   expectations to `test_lab_rules_hand_written_expectations` (the suite fails
   until you do): they pin down what the rule must and must not match.
4. Commit the rule *and* `sigma/generated/`; CI fails if they disagree.
5. `terraform apply`. Metric filters and alarms appear in the catalogue; the hunt
   appears in the workgroup. Add `sigma_<name>` to `scheduled_hunts` to run it daily.

## Supported subset

| Sigma | CloudWatch metric filter | Logs Insights log alarm | Athena hunt |
|-------|--------------------------|-------------------------|-------------|
| `and`, `or`, `not`, parentheses, `1 of` / `all of` (wildcards, `them`) | yes (negation pushed down to fields) | yes | yes |
| strings, lists, `\|all` | yes | yes | yes |
| `*` wildcard | start or end of a value only | anywhere (regex) | anywhere |
| `?` wildcard, escaped literal `\*` | no | yes | yes |
| `contains`, `startswith`, `endswith` | yes | yes | yes |
| case-insensitive matching (Sigma default) | **no**: CloudWatch is case-sensitive | yes (`(?i)` regex) | yes |
| `\|cased` | yes | yes | yes |
| integers, booleans, `null` | yes (`not null` no: CloudWatch has no `EXISTS`) | yes (booleans matched as 1/0 or "true"/"false"; JSON null as absent: checked live) | yes |
| `\|exists: false` / `true` | false only | yes | yes |
| `\|re` (`\|i`) | no | yes (RE2: no lookaround or backreferences) | yes |
| `\|cidr` (IPv4 and IPv6) | no | yes (`isIpInSubnet`, both families) | yes |
| `resources.*` (array fields) | no | no | no |
| keywords, aggregations (`\| count()`), correlations, other modifiers | not converted | not converted | not converted |
| patterns over 1024 characters | no (CloudWatch limit) | queries up to 10,000 characters | yes |

**Semantics.** Both targets follow the Sigma rule that a condition on an absent
field is false, so `not` of it is true. In Athena every comparison is guarded so
it is TRUE or FALSE, never NULL (a NULL survives `NOT` and silently drops the
event). In CloudWatch a negated comparison is written as
`($.f != v || $.f NOT EXISTS || $.f IS NULL)`, so it does not depend on how
CloudWatch treats `!=` on a missing field. Write booleans unquoted (`false`,
not `'false'`): CloudTrail emits real JSON booleans, and CloudWatch compares
types strictly.

**Case.** Sigma matching is case-insensitive; CloudWatch's is not. CloudWatch
conversions therefore assume CloudTrail's own casing, which is exact for
service-generated values (`eventSource`, `eventName`, `userIdentity.type`, ...)
and not for values people type. Prefer the Athena hunt, or `|cased` to be
explicit, for user-controlled fields.

## Using SigmaHQ rules

The [SigmaHQ repository](https://github.com/SigmaHQ/sigma) has many CloudTrail
rules under `rules/cloud/aws/`. Copy the ones you want into `sigma/rules/sigmahq/`
and keep their `author` and `references` fields: SigmaHQ rules are licensed under
the [Detection Rule License](https://github.com/SigmaHQ/Detection-Rule-License),
which requires attribution. Run the converter and read the report; rules outside
the supported subset are listed with the reason.
