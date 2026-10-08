# One metric filter + one alarm per catalogue entry. Alarms fire on the first
# matching event in a 5-minute window and notify the shared alert topic.

resource "aws_cloudwatch_log_metric_filter" "detection" {
  for_each = local.detections

  name           = "${var.name_prefix}-${each.key}"
  log_group_name = var.cloudtrail_log_group
  pattern        = each.value.pattern

  metric_transformation {
    name          = "${var.name_prefix}-${each.key}"
    namespace     = "DetectionLab"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "detection" {
  for_each = local.detections

  alarm_name          = "${var.name_prefix}-${each.key}"
  alarm_description   = "${each.value.description} | ATT&CK: ${each.value.attack}"
  namespace           = "DetectionLab"
  metric_name         = "${var.name_prefix}-${each.key}"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [var.alarm_sns_topic_arn]
  ok_actions    = [var.alarm_sns_topic_arn]

  tags = {
    attack_technique = each.value.attack
  }
}
