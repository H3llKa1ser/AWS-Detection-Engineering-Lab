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
  region     = data.aws_region.current.region
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

# 6. DNS Firewall: enforce, not just observe. Lab VPC only unless opted in.
locals {
  firewall_vpcs = var.dns_firewall_protect_monitored_vpcs ? local.monitored_vpcs : {
    for k, v in local.monitored_vpcs : k => v if k == "lab"
  }
}

module "dns_firewall" {
  source = "./modules/dns-firewall"
  count  = var.enable_dns_firewall ? 1 : 0

  name_prefix             = var.name_prefix
  region                  = local.region
  vpc_ids                 = local.firewall_vpcs
  managed_domain_lists    = var.dns_firewall_managed_lists
  managed_domain_list_ids = var.dns_firewall_managed_list_ids
  block_domains           = var.dns_firewall_block_domains
  allow_domains           = var.dns_firewall_allow_domains
  block_response          = var.dns_firewall_block_response
  block_override_domain   = var.dns_firewall_block_override_domain
  fail_open               = var.dns_firewall_fail_open

  advanced_protections     = var.dns_firewall_advanced_protections
  advanced_alarm_threshold = var.dns_firewall_advanced_alarm_threshold
  alert_topic_arn          = module.alerting.alert_topic_arn
  kms_key_arn              = module.logging.kms_key_arn
  account_id               = local.account_id
  partition                = local.partition
}

check "dns_firewall_visibility" {
  assert {
    condition     = !var.enable_dns_firewall || var.enable_dns_query_logging
    error_message = "DNS Firewall is enabled without DNS query logging: queries will be blocked but nothing records what was blocked, and the dns_firewall_* detections are skipped."
  }
}

check "dns_firewall_has_targets" {
  assert {
    condition     = !var.enable_dns_firewall || length(local.firewall_vpcs) > 0
    error_message = "DNS Firewall is enabled but protects no VPC: set create_lab_vpc = true, or dns_firewall_protect_monitored_vpcs = true with monitored_vpc_ids."
  }
}

# 7. Detection-as-code: metric-filter alarms over CloudTrail, flow and DNS logs.
module "detections" {
  source = "./modules/detections"

  name_prefix         = var.name_prefix
  alarm_sns_topic_arn = module.alerting.alert_topic_arn

  enabled_sources = concat(
    ["cloudtrail"],
    var.enable_vpc_flow_logs ? ["vpc_flow"] : [],
    var.enable_dns_query_logging ? ["dns"] : [],
    var.enable_dns_query_logging && var.enable_dns_firewall ? ["dns_firewall"] : [],
  )

  log_groups = merge(
    { cloudtrail = module.logging.cloudwatch_log_group_name },
    var.enable_vpc_flow_logs ? { vpc_flow = module.vpc_flow_logs[0].log_group_name } : {},
    var.enable_dns_query_logging ? { dns = module.dns_query_logging[0].log_group_name } : {},
    # DNS Firewall verdicts are written into the same Resolver query logs.
    var.enable_dns_query_logging ? { dns_firewall = module.dns_query_logging[0].log_group_name } : {},
  )
}

# 8. Threat hunting: Athena + Glue over the CloudTrail bucket, saved hunts.
module "threat_hunting" {
  source = "./modules/threat-hunting"
  count  = var.enable_threat_hunting ? 1 : 0

  name_prefix            = var.name_prefix
  account_id             = local.account_id
  partition              = local.partition
  region                 = local.region
  cloudtrail_bucket_name = module.logging.cloudtrail_bucket_name
  cloudtrail_bucket_arn  = module.logging.cloudtrail_bucket_arn
  kms_key_arn            = module.logging.kms_key_arn
  projection_start       = var.hunting_projection_start
  lookback_days          = var.hunting_lookback_days
  recent_days            = var.hunting_recent_days
  bytes_scanned_cutoff   = var.hunting_bytes_scanned_cutoff
  scheduled_hunts        = var.enable_scheduled_hunts ? var.scheduled_hunts : []
}

# 9. Scheduled hunts: run selected saved hunts daily, alert only on findings.
module "scheduled_hunts" {
  source = "./modules/scheduled-hunts"
  count  = var.enable_threat_hunting && var.enable_scheduled_hunts && length(var.scheduled_hunts) > 0 ? 1 : 0

  name_prefix       = var.name_prefix
  account_id        = local.account_id
  partition         = local.partition
  hunts             = module.threat_hunting[0].scheduled_hunts
  workgroup_name    = module.threat_hunting[0].workgroup
  hunter_policy_arn = module.threat_hunting[0].hunter_policy_arn
  alert_topic_arn   = module.alerting.alert_topic_arn
  schedule_hour     = var.hunt_schedule_hour
  schedule_timezone = var.hunt_schedule_timezone
}

check "scheduled_hunts_need_hunting" {
  assert {
    condition     = !var.enable_scheduled_hunts || var.enable_threat_hunting
    error_message = "enable_scheduled_hunts has no effect unless enable_threat_hunting = true."
  }
}

# 10. Optional traffic generator that exercises the DNS detections.
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

# 11. Optional automated response to high-signal GuardDuty findings.
module "response" {
  source = "./modules/response"
  count  = var.enable_response_automation ? 1 : 0

  name_prefix     = var.name_prefix
  alert_topic_arn = module.alerting.alert_topic_arn
  partition       = local.partition
}
