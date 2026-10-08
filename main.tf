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
  enable_ipv6 = var.lab_vpc_ipv6
}

locals {
  # Network log lake (Parquet in S3 + Athena). Name computed here so modules can
  # reference it without depending on each other.
  network_logs_bucket = "${var.name_prefix}-network-logs-${local.account_id}-${local.region}"
  lake_flow           = var.enable_network_log_lake && var.enable_threat_hunting && var.enable_vpc_flow_logs
  lake_dns            = var.enable_network_log_lake && var.enable_threat_hunting && var.enable_dns_query_logging
  lake                = local.lake_flow || local.lake_dns

  # Threat intel (curated indicators -> Athena table -> intel hunts).
  intel_bucket = "${var.name_prefix}-threat-intel-${local.account_id}-${local.region}"
  intel        = var.enable_threat_intel && var.enable_threat_hunting

  # Recommended daily schedule for what is deployed (used when scheduled_hunts = null).
  base_hunts = [
    "01_console_login_new_source", "02_console_bruteforce_then_success", "03_permission_probing",
    "05_iam_persistence", "06_defense_evasion_sensor_tampering", "07_new_region_activity",
    "08_data_shared_to_other_accounts", "09_compute_hijacking", "12_root_activity", "13_new_role_assumption_path",
  ]
  recommended_hunts = concat(
    local.base_hunts,
    local.lake_dns ? ["17_dns_tunnel_shape"] : [],
    local.lake_flow ? ["18_flow_new_external_transfer"] : [],
    local.lake_flow && local.lake_dns ? ["20_flow_egress_without_dns"] : [],
    local.intel && local.lake_flow ? ["22_intel_flow_matches"] : [],
    local.intel && local.lake_dns ? ["23_intel_dns_matches"] : [],
    local.intel ? ["24_intel_cloudtrail_source_ip"] : [],
  )
  scheduled_hunt_list = var.scheduled_hunts == null ? local.recommended_hunts : var.scheduled_hunts
}

locals {
  # Static keys so for_each is plannable even though the lab VPC id is computed.
  monitored_vpcs = merge(
    var.create_lab_vpc ? { lab = module.lab_vpc[0].vpc_id } : {},
    { for id in var.monitored_vpc_ids : id => id },
  )
}

# Internal address ranges for the network hunts: every monitored VPC's IPv4
# and IPv6 CIDR blocks (VPC IPv6 addresses are globally routable, so only the
# VPC's own ranges mark them internal), plus extra_internal_cidrs.
data "aws_vpc" "monitored" {
  for_each = local.monitored_vpcs
  id       = each.value
}

locals {
  internal_cidrs = distinct(compact(concat(
    flatten([for v in data.aws_vpc.monitored : [for a in v.cidr_block_associations : a.cidr_block]]),
    [for v in data.aws_vpc.monitored : v.ipv6_cidr_block],
    flatten([for v in data.aws_vpc.monitored : [for a in v.ipv6_cidr_block_associations : a.ipv6_cidr_block]]),
    var.extra_internal_cidrs,
  )))
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

  enable_s3_parquet = local.lake_flow
  s3_bucket_arn     = local.lake_flow ? module.network_log_lake[0].bucket_arn : null
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

  enable_firehose_destination = local.lake_dns
  firehose_arn                = local.lake_dns ? module.network_log_lake[0].firehose_arn : null
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
  scheduled_hunts        = var.enable_scheduled_hunts ? local.scheduled_hunt_list : []
  internal_cidrs         = local.internal_cidrs

  available_sources = concat(
    ["cloudtrail"],
    local.lake_flow ? ["flow"] : [],
    local.lake_dns ? ["dns"] : [],
    local.intel ? ["intel"] : [],
  )
  intel_bucket_arn        = local.intel ? "arn:${local.partition}:s3:::${local.intel_bucket}" : null
  network_logs_bucket_arn = local.lake ? "arn:${local.partition}:s3:::${local.network_logs_bucket}" : null
}

# 8b. Network log lake: flow logs + Resolver query logs as Parquet in S3, with
#     Athena tables in the hunting database.
module "network_log_lake" {
  source = "./modules/network-log-lake"
  count  = local.lake ? 1 : 0

  name_prefix      = var.name_prefix
  account_id       = local.account_id
  partition        = local.partition
  region           = local.region
  bucket_name      = local.network_logs_bucket
  kms_key_arn      = module.logging.kms_key_arn
  database_name    = module.threat_hunting[0].database
  enable_flow      = local.lake_flow
  enable_dns       = local.lake_dns
  projection_start = var.hunting_projection_start
  retention_days   = var.network_lake_retention_days
}

# 8c. Threat intel: curated indicators as an Athena table in the hunting database.
module "threat_intel" {
  source = "./modules/threat-intel"
  count  = local.intel ? 1 : 0

  name_prefix   = var.name_prefix
  account_id    = local.account_id
  partition     = local.partition
  region        = local.region
  bucket_name   = local.intel_bucket
  kms_key_arn   = module.logging.kms_key_arn
  database_name = module.threat_hunting[0].database
  indicator_dir = "${path.root}/${var.intel_indicator_dir}"

  # Upload indicators only after the retro-hunt rule (and the retro queries it
  # runs) exist; otherwise the first retro-hunt is silently missed.
  depends_on = [module.scheduled_hunts]
}

# 9. Scheduled hunts: run selected saved hunts daily, alert only on findings;
#    retro-hunt intel hunts when the indicator set changes.
module "scheduled_hunts" {
  source = "./modules/scheduled-hunts"
  count  = var.enable_threat_hunting && var.enable_scheduled_hunts && length(local.scheduled_hunt_list) > 0 ? 1 : 0

  name_prefix       = var.name_prefix
  account_id        = local.account_id
  partition         = local.partition
  hunts             = module.threat_hunting[0].scheduled_hunts
  workgroup_name    = module.threat_hunting[0].workgroup
  hunter_policy_arn = module.threat_hunting[0].hunter_policy_arn
  alert_topic_arn   = module.alerting.alert_topic_arn
  schedule_hour     = var.hunt_schedule_hour
  schedule_timezone = var.hunt_schedule_timezone

  enable_retro      = local.intel && var.retro_hunt_on_intel_change
  retro_hunts       = local.intel ? module.threat_hunting[0].retro_hunts : {}
  intel_bucket_name = local.intel ? local.intel_bucket : null
}

check "retro_hunts_need_scheduler" {
  assert {
    condition     = !(local.intel && var.retro_hunt_on_intel_change) || (var.enable_scheduled_hunts && length(local.scheduled_hunt_list) > 0)
    error_message = "Retro-hunting on intel changes uses the scheduled-hunts state machine, which is not deployed (enable_scheduled_hunts = false or no hunts scheduled). New indicators will only match new traffic."
  }
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
