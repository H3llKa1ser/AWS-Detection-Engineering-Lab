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
