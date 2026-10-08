# ---------------------------------------------------------------------------
# AWS Detection Engineering Lab - root composition
#
# Wires together the telemetry, threat-detection, detection-as-code, alerting
# and (optional) response layers. Every layer is a module so each concern can
# be read, reviewed and reused independently.
# ---------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_partition" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.name
  partition  = data.aws_partition.current.partition
}

# 1. Telemetry foundation: CloudTrail -> S3 + CloudWatch Logs, optional CMK.
module "logging" {
  source = "./modules/logging"

  name_prefix        = var.name_prefix
  log_retention_days = var.log_retention_days
  kms_encrypt_logs   = var.kms_encrypt_logs
  account_id         = local.account_id
  partition          = local.partition
  region             = local.region
}

# 2. Configuration recording + baseline compliance rules.
module "config" {
  source = "./modules/config"
  count  = var.enable_config ? 1 : 0

  name_prefix = var.name_prefix
  account_id  = local.account_id
  partition   = local.partition
}

# 3. Managed threat detection: GuardDuty + Security Hub.
module "threat_detection" {
  source = "./modules/threat-detection"

  name_prefix        = var.name_prefix
  enable_guardduty   = var.enable_guardduty
  enable_securityhub = var.enable_securityhub
  partition          = local.partition
  region             = local.region
}

# 4. Alerting fabric: SNS topic + EventBridge routing for findings.
module "alerting" {
  source = "./modules/alerting"

  name_prefix            = var.name_prefix
  alert_email            = var.alert_email
  min_guardduty_severity = var.min_guardduty_severity
  enable_guardduty       = var.enable_guardduty
  enable_securityhub     = var.enable_securityhub
  account_id             = local.account_id
  partition              = local.partition
  region                 = local.region
}

# 5. Detection-as-code: CloudWatch metric-filter alarms over CloudTrail.
module "detections" {
  source = "./modules/detections"

  name_prefix          = var.name_prefix
  cloudtrail_log_group = module.logging.cloudwatch_log_group_name
  alarm_sns_topic_arn  = module.alerting.alert_topic_arn
}

# 6. Optional automated response to high-signal GuardDuty findings.
module "response" {
  source = "./modules/response"
  count  = var.enable_response_automation ? 1 : 0

  name_prefix     = var.name_prefix
  alert_topic_arn = module.alerting.alert_topic_arn
  partition       = local.partition
}
