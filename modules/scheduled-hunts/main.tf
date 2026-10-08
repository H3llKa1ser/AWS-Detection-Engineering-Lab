# ---------------------------------------------------------------------------
# Scheduled hunts: EventBridge Scheduler -> Step Functions -> Athena -> SNS
#
# Daily, the state machine runs each selected hunt's *scheduled variant* (a
# saved query reporting only the last 24h window), and publishes to the alert
# topic only when a hunt returns rows or fails to run. No Lambda code: Step
# Functions' native Athena and SNS integrations do the work.
#
# Two alarms make silence trustworthy:
#   executions-failed  the run itself broke
#   no-successful-run  nothing completed for two consecutive days (dead man's
#                      switch: a scheduler that stopped would otherwise look
#                      exactly like a clean week)
# ---------------------------------------------------------------------------

locals {
  definition = templatefile("${path.module}/statemachine.asl.json.tftpl", {
    partition       = var.partition
    workgroup       = var.workgroup_name
    topic_arn       = var.alert_topic_arn
    name_prefix     = var.name_prefix
    max_concurrency = var.max_concurrency
    sample_rows     = var.sample_rows
    max_results     = var.sample_rows + 1
  })

  # Scheduler input: one item per hunt, in a stable order.
  input = jsonencode({
    hunts = [for k in sort(keys(var.hunts)) : {
      name         = k
      title        = var.hunts[k].title
      attack       = var.hunts[k].attack
      namedQueryId = var.hunts[k].named_query_id
    }]
  })
}

# --- State machine and its role ---------------------------------------------------
data "aws_iam_policy_document" "sfn_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["states.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "sfn" {
  name               = "${var.name_prefix}-scheduled-hunts"
  assume_role_policy = data.aws_iam_policy_document.sfn_assume.json
}

# The scheduler hunts with exactly a human hunter's permissions: query the
# workgroup, read CloudTrail (never write), use the lab key...
resource "aws_iam_role_policy_attachment" "hunter" {
  role       = aws_iam_role.sfn.name
  policy_arn = var.hunter_policy_arn
}

# ...plus the one thing a human hunter does not need: publishing alerts.
data "aws_iam_policy_document" "sfn_publish" {
  statement {
    sid       = "PublishHuntAlerts"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [var.alert_topic_arn]
  }
}

resource "aws_iam_role_policy" "sfn_publish" {
  name   = "${var.name_prefix}-scheduled-hunts-publish"
  role   = aws_iam_role.sfn.id
  policy = data.aws_iam_policy_document.sfn_publish.json
}

resource "aws_sfn_state_machine" "hunts" {
  name       = "${var.name_prefix}-scheduled-hunts"
  role_arn   = aws_iam_role.sfn.arn
  type       = "STANDARD" # .sync integrations need Standard workflows
  definition = local.definition

  depends_on = [aws_iam_role_policy_attachment.hunter, aws_iam_role_policy.sfn_publish]
}

# --- Daily schedule -------------------------------------------------------------------
data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.name_prefix}-scheduled-hunts-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

data "aws_iam_policy_document" "scheduler_start" {
  statement {
    effect    = "Allow"
    actions   = ["states:StartExecution"]
    resources = [aws_sfn_state_machine.hunts.arn]
  }
}

resource "aws_iam_role_policy" "scheduler_start" {
  name   = "${var.name_prefix}-scheduled-hunts-start"
  role   = aws_iam_role.scheduler.id
  policy = data.aws_iam_policy_document.scheduler_start.json
}

resource "aws_scheduler_schedule" "daily" {
  name                         = "${var.name_prefix}-daily-hunts"
  description                  = "Run ${length(var.hunts)} scheduled threat hunts daily."
  schedule_expression          = "cron(0 ${var.schedule_hour} * * ? *)"
  schedule_expression_timezone = var.schedule_timezone

  flexible_time_window {
    mode = "OFF" # fixed start time keeps the 24h reporting windows contiguous
  }

  target {
    arn      = aws_sfn_state_machine.hunts.arn
    role_arn = aws_iam_role.scheduler.arn
    input    = local.input

    retry_policy {
      maximum_retry_attempts       = 3
      maximum_event_age_in_seconds = 3600
    }
  }
}

# --- Make silence trustworthy -------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "executions_failed" {
  alarm_name          = "${var.name_prefix}-scheduled_hunts_execution_failed"
  alarm_description   = "The scheduled-hunts run failed as a whole (individual hunt failures alert separately). Hunting is blind until fixed."
  namespace           = "AWS/States"
  metric_name         = "ExecutionsFailed"
  dimensions          = { StateMachineArn = aws_sfn_state_machine.hunts.arn }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.alert_topic_arn]
}

resource "aws_cloudwatch_metric_alarm" "no_successful_run" {
  alarm_name          = "${var.name_prefix}-scheduled_hunts_not_running"
  alarm_description   = "Dead man's switch: no successful scheduled-hunts run on two consecutive days. Without this, a stopped scheduler looks exactly like a clean week."
  namespace           = "AWS/States"
  metric_name         = "ExecutionsSucceeded"
  dimensions          = { StateMachineArn = aws_sfn_state_machine.hunts.arn }
  statistic           = "Sum"
  period              = 86400
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching" # no metric at all means no run at all
  alarm_actions       = [var.alert_topic_arn]
  ok_actions          = [var.alert_topic_arn]
}
