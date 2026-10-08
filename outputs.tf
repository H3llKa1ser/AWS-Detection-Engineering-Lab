output "cloudtrail_bucket" {
  description = "S3 bucket storing CloudTrail logs."
  value       = module.logging.cloudtrail_bucket_name
}

output "cloudtrail_log_group" {
  description = "CloudWatch Logs group the detection metric filters run against."
  value       = module.logging.cloudwatch_log_group_name
}

output "alert_topic_arn" {
  description = "SNS topic that detections, GuardDuty and Security Hub publish to. Subscribe your pager/Slack/email here."
  value       = module.alerting.alert_topic_arn
}

output "guardduty_detector_id" {
  description = "GuardDuty detector id (null when disabled)."
  value       = module.threat_detection.guardduty_detector_id
}

output "deployed_detections" {
  description = "Names of the CloudWatch metric-filter detections that were deployed."
  value       = module.detections.detection_names
}

output "detections_by_source" {
  description = "Deployed detections grouped by telemetry source."
  value       = module.detections.detections_by_source
}

output "monitored_vpcs" {
  description = "VPCs with flow logs and/or DNS query logging attached."
  value       = local.monitored_vpcs
}

output "vpc_flow_log_group" {
  description = "CloudWatch Logs group receiving VPC Flow Logs (null when disabled)."
  value       = var.enable_vpc_flow_logs ? module.vpc_flow_logs[0].log_group_name : null
}

output "dns_query_log_group" {
  description = "CloudWatch Logs group receiving Route 53 Resolver query logs (null when disabled)."
  value       = var.enable_dns_query_logging ? module.dns_query_logging[0].log_group_name : null
}

output "traffic_generator_instance_id" {
  description = "Traffic generator instance id (null when not deployed)."
  value       = length(module.traffic_generator) > 0 ? module.traffic_generator[0].instance_id : null
}

output "dns_firewall_rules" {
  description = "Effective DNS Firewall rule order (priority => action and list). Null when disabled."
  value       = var.enable_dns_firewall ? module.dns_firewall[0].rules : null
}

output "dns_firewall_managed_list_ids" {
  description = "Resolved managed-list IDs, to match firewall_domain_list_id in query logs."
  value       = var.enable_dns_firewall ? module.dns_firewall[0].managed_domain_list_ids : null
}

output "dns_firewall_advanced_alarms" {
  description = "Alarms raised by DNS Firewall Advanced verdicts (null when the firewall is disabled)."
  value       = var.enable_dns_firewall ? module.dns_firewall[0].advanced_alarm_names : null
}

output "dns_firewall_advanced_event_log" {
  description = "Log group holding raw DNS Firewall Advanced EventBridge events, for triage."
  value       = var.enable_dns_firewall ? module.dns_firewall[0].advanced_event_log_group : null
}

output "hunting_workgroup" {
  description = "Athena workgroup holding the saved hunts (null when disabled)."
  value       = var.enable_threat_hunting ? module.threat_hunting[0].workgroup : null
}

output "hunting_table" {
  description = "Glue/Athena table over CloudTrail, as database.table."
  value       = var.enable_threat_hunting ? module.threat_hunting[0].table : null
}

output "hunter_policy_arn" {
  description = "Attach to the identities that run hunts."
  value       = var.enable_threat_hunting ? module.threat_hunting[0].hunter_policy_arn : null
}

output "saved_hunts" {
  description = "Saved hunt => MITRE ATT&CK mapping."
  value       = var.enable_threat_hunting ? module.threat_hunting[0].saved_hunts : null
}

output "scheduled_hunts" {
  description = "When the scheduled hunts run and which ones (null when disabled)."
  value       = length(module.scheduled_hunts) > 0 ? module.scheduled_hunts[0].schedule : null
}

output "run_scheduled_hunts_now" {
  description = "CLI command to run the scheduled hunts immediately with the schedule's own input."
  value       = length(module.scheduled_hunts) > 0 ? module.scheduled_hunts[0].run_now : null
}

output "network_log_lake" {
  description = "Network Parquet tables in the hunting database (null when the lake is disabled)."
  value = local.lake ? {
    bucket     = local.network_logs_bucket
    flow_table = local.lake_flow ? "${module.threat_hunting[0].database}.${module.network_log_lake[0].flow_table}" : null
    dns_table  = local.lake_dns ? "${module.threat_hunting[0].database}.${module.network_log_lake[0].dns_table}" : null
  } : null
}

output "threat_intel" {
  description = "Indicator table and counts per source in the applied set (null when intel is off)."
  value = local.intel ? {
    table      = "${module.threat_hunting[0].database}.${module.threat_intel[0].table}"
    by_source  = module.threat_intel[0].indicators_by_source
    retro_rule = length(module.scheduled_hunts) > 0 ? module.scheduled_hunts[0].retro_trigger : null
  } : null
}

output "internal_cidrs" {
  description = "Ranges the network hunts treat as internal, on top of the built-in private and special ranges."
  value       = local.internal_cidrs
}

output "sigma" {
  description = "Sigma rules deployed as CloudWatch metric filters and as Athena hunts (null when disabled)."
  value = var.enable_sigma ? {
    metric_filters = sort(keys(local.sigma_metric_filters))
    hunts          = sort([for f in fileset("${local.sigma_dir}/hunts", "*.sql") : trimsuffix(f, ".sql")])
  } : null
}

output "scheduled_hunts_state_machine_arn" {
  description = "State machine that runs scheduled hunts and retro-hunts (null when disabled)."
  value       = length(module.scheduled_hunts) > 0 ? module.scheduled_hunts[0].state_machine_arn : null
}
