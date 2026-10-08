# ---------------------------------------------------------------------------
# Delegated administrator account: GuardDuty and Security Hub for the whole
# organization, in every region, from one account.
#
#   GuardDuty     per region: the admin's own detector, the organization
#                 configuration (auto-enable members) and protection plans.
#                 Members are enabled by GuardDuty itself; it can take up to
#                 24 hours to reach every account.
#   Security Hub  central configuration: a finding aggregator in the home
#                 region linking the other regions, the organization set to
#                 CENTRAL, and a configuration policy (standards, controls)
#                 associated with the root or OUs. Policies are managed only
#                 from the home region.
# ---------------------------------------------------------------------------

locals {
  enabled_features = { for k, v in var.guardduty_features : k => v if v != "NONE" }
  linked_regions   = sort([for r in var.regions : r if r != var.home_region])
  region_features  = { for pair in setproduct(var.regions, keys(var.guardduty_features)) : "${pair[0]}/${pair[1]}" => { region = pair[0], feature = pair[1] } }
  admin_features   = { for k, v in local.region_features : k => v if contains(keys(local.enabled_features), v.feature) }
}

# --- GuardDuty ---------------------------------------------------------------------
resource "aws_guardduty_detector" "admin" {
  for_each = toset(var.regions)

  region = each.value
  enable = true
}

resource "aws_guardduty_organization_configuration" "this" {
  for_each = toset(var.regions)

  region                           = each.value
  detector_id                      = aws_guardduty_detector.admin[each.value].id
  auto_enable_organization_members = var.auto_enable_members
}

resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each = local.region_features

  region      = each.value.region
  detector_id = aws_guardduty_detector.admin[each.value.region].id
  name        = each.value.feature
  auto_enable = var.guardduty_features[each.value.feature]

  depends_on = [aws_guardduty_organization_configuration.this]
}

# The admin account's own detector gets the same enabled plans.
resource "aws_guardduty_detector_feature" "admin" {
  for_each = local.admin_features

  region      = each.value.region
  detector_id = aws_guardduty_detector.admin[each.value.region].id
  name        = each.value.feature
  status      = "ENABLED"
}

# --- Security Hub central configuration --------------------------------------------------
resource "aws_securityhub_finding_aggregator" "home" {
  region            = var.home_region
  linking_mode      = length(local.linked_regions) > 0 ? "SPECIFIED_REGIONS" : "NO_REGIONS"
  specified_regions = length(local.linked_regions) > 0 ? local.linked_regions : null
}

resource "aws_securityhub_organization_configuration" "central" {
  region                = var.home_region
  auto_enable           = false  # required for CENTRAL: policies decide
  auto_enable_standards = "NONE" # required for CENTRAL

  organization_configuration {
    configuration_type = "CENTRAL"
  }

  depends_on = [aws_securityhub_finding_aggregator.home]
}

resource "aws_securityhub_configuration_policy" "org" {
  region      = var.home_region
  name        = "organization-baseline"
  description = "Security Hub on, with the lab's standards, for every associated account and linked region."

  configuration_policy {
    service_enabled       = true
    enabled_standard_arns = [for s in var.securityhub_standards : "arn:${var.partition}:securityhub:${var.home_region}::standards/${s}"]

    security_controls_configuration {
      disabled_control_identifiers = var.securityhub_disabled_controls
    }
  }

  depends_on = [aws_securityhub_organization_configuration.central]
}

resource "aws_securityhub_configuration_policy_association" "targets" {
  for_each = toset(var.policy_targets)

  region    = var.home_region
  target_id = each.value
  policy_id = aws_securityhub_configuration_policy.org.id
}
