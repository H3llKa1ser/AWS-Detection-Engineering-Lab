# ---------------------------------------------------------------------------
# Alerting fabric
#   - One SNS topic that every signal source publishes to
#   - EventBridge rules forward GuardDuty + Security Hub findings
#   - CloudWatch metric-filter alarms also target this topic (wired in root)
# ---------------------------------------------------------------------------

resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
}

# Allow CloudWatch alarms and EventBridge to publish to the topic.
data "aws_iam_policy_document" "topic" {
  statement {
    sid     = "AllowServicesToPublish"
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "cloudwatch.amazonaws.com"]
    }
    resources = [aws_sns_topic.alerts.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.topic.json
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- GuardDuty findings -> SNS ---------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty" {
  count       = var.enable_guardduty ? 1 : 0
  name        = "${var.name_prefix}-guardduty-findings"
  description = "Forward GuardDuty findings at or above the configured severity."
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.min_guardduty_severity] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "guardduty" {
  count     = var.enable_guardduty ? 1 : 0
  rule      = aws_cloudwatch_event_rule.guardduty[0].name
  target_id = "sns"
  arn       = aws_sns_topic.alerts.arn

  input_transformer {
    input_paths = {
      severity = "$.detail.severity"
      type     = "$.detail.type"
      title    = "$.detail.title"
      region   = "$.region"
      account  = "$.account"
    }
    input_template = "\"GuardDuty [<severity>] <type> in <account>/<region>: <title>\""
  }
}

# --- Security Hub findings -> SNS ------------------------------------------
resource "aws_cloudwatch_event_rule" "securityhub" {
  count       = var.enable_securityhub ? 1 : 0
  name        = "${var.name_prefix}-securityhub-findings"
  description = "Forward new high/critical Security Hub findings."
  event_pattern = jsonencode({
    source      = ["aws.securityhub"]
    detail-type = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity    = { Label = ["HIGH", "CRITICAL"] }
        RecordState = ["ACTIVE"]
        Workflow    = { Status = ["NEW"] }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub" {
  count     = var.enable_securityhub ? 1 : 0
  rule      = aws_cloudwatch_event_rule.securityhub[0].name
  target_id = "sns"
  arn       = aws_sns_topic.alerts.arn
}
