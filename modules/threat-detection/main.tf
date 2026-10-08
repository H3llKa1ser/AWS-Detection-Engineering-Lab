# ---------------------------------------------------------------------------
# Managed threat detection
#   - GuardDuty: continuous analysis of CloudTrail, VPC Flow Logs and DNS logs
#   - Security Hub: aggregates findings and scores them against standards
# ---------------------------------------------------------------------------

resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true
}

# Protection plans as detector features (the datasources block is deprecated
# in hashicorp/aws 6.x). Foundational sources (CloudTrail management events,
# VPC flow logs, DNS logs) need no feature: they are always on.
resource "aws_guardduty_detector_feature" "main" {
  for_each = var.enable_guardduty ? toset(["S3_DATA_EVENTS", "EBS_MALWARE_PROTECTION"]) : toset([])

  detector_id = aws_guardduty_detector.main[0].id
  name        = each.value
  status      = "ENABLED"
}

resource "aws_securityhub_account" "main" {
  count                     = var.enable_securityhub ? 1 : 0
  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true
}

resource "aws_securityhub_standards_subscription" "foundational" {
  count         = var.enable_securityhub ? 1 : 0
  standards_arn = "arn:${var.partition}:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "cis" {
  count         = var.enable_securityhub ? 1 : 0
  standards_arn = "arn:${var.partition}:securityhub:${var.region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
  depends_on    = [aws_securityhub_account.main]
}
