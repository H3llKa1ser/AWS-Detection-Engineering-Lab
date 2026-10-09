module "alerting" {
  source = "../../../modules/alerting"

  name_prefix            = var.name_prefix
  alert_email            = ""
  min_guardduty_severity = 7
  enable_guardduty       = true
  enable_securityhub     = true
  account_id             = local.account_id
  partition              = local.partition
  region                 = var.region
}
