# Apply with credentials for the DELEGATED ADMINISTRATOR account, after
# org/management. See docs/multi-account.md.

provider "aws" {
  region = var.home_region
}

module "security_admin" {
  source = "../../modules/org-security-admin"

  home_region                   = var.home_region
  regions                       = var.regions
  partition                     = var.partition
  auto_enable_members           = var.auto_enable_members
  guardduty_features            = var.guardduty_features
  securityhub_standards         = var.securityhub_standards
  securityhub_disabled_controls = var.securityhub_disabled_controls
  policy_targets                = var.policy_targets
}

# Findings from every account and region reach one topic: GuardDuty findings
# for members arrive in this account, and Security Hub aggregates every linked
# region (GuardDuty findings included) into the home region's event bus.
module "alerting" {
  source = "../../modules/alerting"

  name_prefix            = var.name_prefix
  alert_email            = var.alert_email
  min_guardduty_severity = var.min_guardduty_severity
  enable_guardduty       = true
  enable_securityhub     = true
  account_id             = var.delegated_admin_account_id
  partition              = var.partition
  region                 = var.home_region
}

check "running_in_the_delegated_admin_account" {
  data "aws_caller_identity" "current" {}

  assert {
    condition     = data.aws_caller_identity.current.account_id == var.delegated_admin_account_id
    error_message = "These credentials are not for delegated_admin_account_id."
  }
}

output "guardduty_detectors" {
  value = module.security_admin.guardduty_detectors
}

output "securityhub_linked_regions" {
  value = module.security_admin.linked_regions
}

output "alert_topic_arn" {
  value = module.alerting.alert_topic_arn
}
