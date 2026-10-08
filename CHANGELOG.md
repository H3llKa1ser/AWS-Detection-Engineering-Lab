# Changelog

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
