# ---------------------------------------------------------------------------
# Organizations management account: delegate GuardDuty and Security Hub
#
# Deliberately small: AWS recommends doing as little as possible in the
# management account. Everything else is configured by the delegated
# administrator (modules/org-security-admin).
#
#   GuardDuty     needs Organizations trusted access before an API-designated
#                 delegated administrator (only its console enables it for
#                 you), and is delegated in EVERY region, to the same account.
#   Security Hub  enables trusted access itself when delegated; must be
#                 enabled in the management account first; delegated in the
#                 home region, from which central configuration is managed.
# ---------------------------------------------------------------------------

# hashicorp/aws can only enable trusted access through aws_organizations_organization,
# which would take over the whole organization (Control Tower, landing zones).
# One idempotent CLI call instead.
resource "terraform_data" "guardduty_trusted_access" {
  count = var.enable_guardduty_trusted_access ? 1 : 0

  triggers_replace = [var.management_account_id]

  provisioner "local-exec" {
    command = "aws organizations enable-aws-service-access --service-principal guardduty.amazonaws.com"
  }
}

resource "aws_guardduty_organization_admin_account" "this" {
  for_each = toset(var.regions)

  region           = each.value
  admin_account_id = var.delegated_admin_account_id

  depends_on = [terraform_data.guardduty_trusted_access]

  lifecycle {
    # Removing the GuardDuty delegated administrator removes EVERY member account
    # from it. Tearing down is deliberate: see docs/multi-account.md.
    prevent_destroy = true

    precondition {
      condition     = var.delegated_admin_account_id != var.management_account_id
      error_message = "The delegated administrator must be a member account, not the management account."
    }
  }
}

# Security Hub must be on in the management account before it can delegate.
# Standards stay off here: the central configuration policy decides them.
resource "aws_securityhub_account" "management" {
  region                   = var.home_region
  enable_default_standards = false
}

resource "aws_securityhub_organization_admin_account" "this" {
  region           = var.home_region
  admin_account_id = var.delegated_admin_account_id

  depends_on = [aws_securityhub_account.management]

  lifecycle {
    # Changing or removing the Security Hub delegated administrator stops central
    # configuration for the whole organization.
    prevent_destroy = true
  }
}
