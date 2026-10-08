# ---------------------------------------------------------------------------
# Managed threat detection
#   - GuardDuty: continuous analysis of CloudTrail, VPC Flow Logs and DNS logs
#   - Security Hub: aggregates findings and scores them against standards
# ---------------------------------------------------------------------------

resource "aws_guardduty_detector" "main" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }
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
