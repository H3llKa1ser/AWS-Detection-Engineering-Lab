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
