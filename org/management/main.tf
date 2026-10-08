# Apply ONCE, with credentials for the Organizations MANAGEMENT account, before
# org/security-admin. See docs/multi-account.md.

provider "aws" {
  region = var.home_region
}

module "delegation" {
  source = "../../modules/org-delegation"

  management_account_id           = var.management_account_id
  delegated_admin_account_id      = var.delegated_admin_account_id
  home_region                     = var.home_region
  regions                         = var.regions
  enable_guardduty_trusted_access = var.enable_guardduty_trusted_access
}

# With real credentials, confirm this really is the management account.
# (A check warns instead of failing, so an offline plan still works.)
check "running_in_the_management_account" {
  data "aws_caller_identity" "current" {}

  assert {
    condition     = data.aws_caller_identity.current.account_id == var.management_account_id
    error_message = "These credentials are not for management_account_id; delegation only works from the Organizations management account."
  }
}

output "guardduty_delegated_regions" {
  value = module.delegation.guardduty_delegated_regions
}

output "securityhub_delegated_admin" {
  value = module.delegation.securityhub_delegated_admin
}
