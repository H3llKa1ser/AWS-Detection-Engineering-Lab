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

# 5. Network telemetry: an isolated lab VPC plus any existing VPCs you list.
module "lab_vpc" {
  source = "./modules/lab-vpc"
  count  = var.create_lab_vpc ? 1 : 0

  name_prefix = var.name_prefix
  cidr_block  = var.lab_vpc_cidr
}

locals {
  # Static keys so for_each is plannable even though the lab VPC id is computed.
  monitored_vpcs = merge(
    var.create_lab_vpc ? { lab = module.lab_vpc[0].vpc_id } : {},
    { for id in var.monitored_vpc_ids : id => id },
  )
}

module "vpc_flow_logs" {
  source = "./modules/vpc-flow-logs"
  count  = var.enable_vpc_flow_logs ? 1 : 0

  name_prefix        = var.name_prefix
  vpc_ids            = local.monitored_vpcs
  log_retention_days = var.network_log_retention_days
  kms_key_arn        = module.logging.kms_key_arn
  account_id         = local.account_id
  partition          = local.partition
  region             = local.region
}

module "dns_query_logging" {
  source = "./modules/dns-query-logging"
  count  = var.enable_dns_query_logging ? 1 : 0

  name_prefix        = var.name_prefix
  vpc_ids            = local.monitored_vpcs
  log_retention_days = var.network_log_retention_days
  kms_key_arn        = module.logging.kms_key_arn
  account_id         = local.account_id
  partition          = local.partition
  region             = local.region
}

# 6. Detection-as-code: metric-filter alarms over CloudTrail, flow and DNS logs.
module "detections" {
  source = "./modules/detections"

  name_prefix         = var.name_prefix
  alarm_sns_topic_arn = module.alerting.alert_topic_arn

  enabled_sources = concat(
    ["cloudtrail"],
    var.enable_vpc_flow_logs ? ["vpc_flow"] : [],
    var.enable_dns_query_logging ? ["dns"] : [],
  )

  log_groups = merge(
    { cloudtrail = module.logging.cloudwatch_log_group_name },
    var.enable_vpc_flow_logs ? { vpc_flow = module.vpc_flow_logs[0].log_group_name } : {},
    var.enable_dns_query_logging ? { dns = module.dns_query_logging[0].log_group_name } : {},
  )
}

# 7. Optional traffic generator that exercises the DNS detections.
module "traffic_generator" {
  source = "./modules/traffic-generator"
  count  = var.deploy_traffic_generator && var.create_lab_vpc ? 1 : 0

  name_prefix = var.name_prefix
  vpc_id      = module.lab_vpc[0].vpc_id
  subnet_id   = module.lab_vpc[0].private_subnet_id
}

check "traffic_generator_needs_lab_vpc" {
  assert {
    condition     = !var.deploy_traffic_generator || var.create_lab_vpc
    error_message = "deploy_traffic_generator = true has no effect unless create_lab_vpc = true."
  }
}

# 8. Optional automated response to high-signal GuardDuty findings.
module "response" {
  source = "./modules/response"
  count  = var.enable_response_automation ? 1 : 0

  name_prefix     = var.name_prefix
  alert_topic_arn = module.alerting.alert_topic_arn
  partition       = local.partition
}
