# ---------------------------------------------------------------------------
# Detection engine: one metric filter + one alarm per active catalogue entry.
#
# Catalogue entries come from catalogue.tf (CloudTrail) and
# catalogue_network.tf (VPC Flow Logs, DNS). Entries are normalised here so
# every detection has the same shape, then filtered to the telemetry sources
# that are actually deployed.
# ---------------------------------------------------------------------------

locals {
  all_detections = {
    for name, d in merge(local.detections, local.network_detections, var.extra_detections) : name => {
      source      = try(d.source, "cloudtrail")
      description = d.description
      attack      = d.attack
      threshold   = try(d.threshold, 1)
      pattern = try(
        d.pattern,
        "[${join(", ", [for f in local.flow_fields : "${f}${lookup(d.flow_match, f, "")}"])}]"
      )
    }
  }

  active_detections = {
    for name, d in local.all_detections : name => d
    if contains(var.enabled_sources, d.source)
  }
}

resource "aws_cloudwatch_log_metric_filter" "detection" {
  for_each = local.active_detections

  name           = "${var.name_prefix}-${each.key}"
  log_group_name = var.log_groups[each.value.source]
  pattern        = each.value.pattern

  metric_transformation {
    name          = "${var.name_prefix}-${each.key}"
    namespace     = "DetectionLab"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "detection" {
  for_each = local.active_detections

  alarm_name          = "${var.name_prefix}-${each.key}"
  alarm_description   = "[${each.value.source}] ${each.value.description} | ATT&CK: ${each.value.attack}"
  namespace           = "DetectionLab"
  metric_name         = aws_cloudwatch_log_metric_filter.detection[each.key].metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = each.value.threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [var.alarm_sns_topic_arn]
  ok_actions    = [var.alarm_sns_topic_arn]

  tags = {
    attack_technique = each.value.attack
    telemetry_source = each.value.source
  }
}
