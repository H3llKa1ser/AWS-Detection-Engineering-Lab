# ---------------------------------------------------------------------------
# Sigma rules as CloudWatch Logs Insights queries: a second real-time path
#
# Metric filters are case-sensitive and cannot test for a field or an IP range,
# so some Sigma rules convert to them only with caveats or not at all. Logs
# Insights can express the full supported subset with Sigma's semantics, over
# the same CloudTrail log group. Per rule:
#
#   saved query   aws_cloudwatch_query_definition (Logs Insights console)
#   log alarm     awscc_cloudwatch_log_alarm: CloudWatch runs the query on a
#                 schedule (an AWS-managed scheduled query), counts matches,
#                 and alarms at >= 1 to the shared alert topic
# ---------------------------------------------------------------------------

locals {
  log_group_arn = "arn:${var.partition}:logs:${var.region}:${var.account_id}:log-group:${var.log_group_name}"
}

resource "aws_cloudwatch_query_definition" "sigma" {
  for_each = var.rules

  name            = "${var.name_prefix}/sigma/${each.key}"
  log_group_names = [var.log_group_name]
  query_string    = each.value.saved_query
}

# Execution role for the scheduled queries, as AWS documents it: trusts the
# CloudWatch Logs service, may run Logs Insights queries on this log group only.
data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["logs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "query" {
  count              = var.enable_alarms && length(var.rules) > 0 ? 1 : 0
  name               = "${var.name_prefix}-sigma-insights-query"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "query" {
  statement {
    sid       = "RunInsightsQueriesOnTheCloudTrailLogGroup"
    effect    = "Allow"
    actions   = ["logs:StartQuery", "logs:StopQuery", "logs:GetQueryResults", "logs:DescribeLogGroups"]
    resources = [local.log_group_arn, "${local.log_group_arn}:*"]
  }
  dynamic "statement" {
    for_each = var.kms_key_arn == null ? [] : [1]
    content {
      sid       = "ReadEncryptedLogGroup"
      effect    = "Allow"
      actions   = ["kms:Decrypt"]
      resources = [var.kms_key_arn]
      condition {
        test     = "StringEquals"
        variable = "kms:ViaService"
        values   = ["logs.${var.region}.amazonaws.com"]
      }
    }
  }
}

resource "aws_iam_role_policy" "query" {
  count  = length(aws_iam_role.query)
  name   = "${var.name_prefix}-sigma-insights-query"
  role   = aws_iam_role.query[0].id
  policy = data.aws_iam_policy_document.query.json
}

resource "awscc_cloudwatch_log_alarm" "sigma" {
  for_each = var.enable_alarms ? var.rules : {}

  alarm_name          = "${var.name_prefix}-insights-${each.key}"
  alarm_description   = "[insights] Sigma: ${each.value.title} (${each.value.level}) | ATT&CK: ${each.value.attack}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  # One run with a match is enough (1 out of 1), as for the metric-filter alarms.
  query_results_to_evaluate = 1
  query_results_to_alarm    = 1
  treat_missing_data        = "notBreaching"
  alarm_actions             = [var.alert_topic_arn]
  ok_actions                = [var.alert_topic_arn]

  scheduled_query_configuration = {
    query_string             = each.value.alarm_query
    log_group_identifiers    = [var.log_group_name]
    scheduled_query_role_arn = aws_iam_role.query[0].arn
    aggregation_expression   = "count(*)"
    schedule_configuration = {
      schedule_expression = "rate(${var.schedule_minutes} minutes)"
      start_time_offset   = var.lookback_minutes * 60
    }
  }

  tags = [{ key = "Project", value = var.name_prefix }, { key = "SigmaRule", value = each.key }]

  depends_on = [aws_iam_role_policy.query]
}
