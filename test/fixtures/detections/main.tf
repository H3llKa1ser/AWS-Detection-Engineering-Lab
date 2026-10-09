# The detection catalogue plus the Sigma metric filters on a stand-in CloudTrail
# log group, so tests can write events straight into it (no CloudTrail delay).
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/${var.name_prefix}/terratest/cloudtrail"
  retention_in_days = 1
}

resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
}

module "detections" {
  source = "../../../modules/detections"

  name_prefix         = var.name_prefix
  alarm_sns_topic_arn = aws_sns_topic.alerts.arn
  enabled_sources     = ["cloudtrail"]
  log_groups          = { cloudtrail = aws_cloudwatch_log_group.cloudtrail.name }
  extra_detections    = jsondecode(file("${path.module}/../../../sigma/generated/metric_filters.json"))
}

output "log_group" { value = aws_cloudwatch_log_group.cloudtrail.name }
output "topic_arn" { value = aws_sns_topic.alerts.arn }
output "detection_names" { value = module.detections.detection_names }
