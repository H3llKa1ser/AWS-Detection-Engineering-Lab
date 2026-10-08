# ---------------------------------------------------------------------------
# Optional automated response (disabled by default)
#
# EventBridge routes a specific, low-false-positive GuardDuty finding type to a
# Lambda that revokes the over-permissive security-group rule that triggered it.
# Treat this as a demonstration of SOAR-lite patterns, not a blanket auto-fix.
# ---------------------------------------------------------------------------

data "archive_file" "remediate" {
  type        = "zip"
  source_file = "${path.module}/src/remediate.py"
  output_path = "${path.module}/build/remediate.zip"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.name_prefix}-response-lambda"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "Logs"
    effect    = "Allow"
    actions   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["arn:${var.partition}:logs:*:*:*"]
  }
  statement {
    sid       = "RevokeSg"
    effect    = "Allow"
    actions   = ["ec2:RevokeSecurityGroupIngress", "ec2:DescribeSecurityGroups"]
    resources = ["*"]
  }
  statement {
    sid       = "Notify"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [var.alert_topic_arn]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${var.name_prefix}-response-lambda"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "remediate" {
  function_name    = "${var.name_prefix}-guardduty-response"
  role             = aws_iam_role.lambda.arn
  handler          = "remediate.handler"
  runtime          = "python3.12"
  timeout          = 30
  filename         = data.archive_file.remediate.output_path
  source_code_hash = data.archive_file.remediate.output_base64sha256

  environment {
    variables = {
      ALERT_TOPIC_ARN = var.alert_topic_arn
    }
  }
}

resource "aws_cloudwatch_event_rule" "portprobe" {
  name        = "${var.name_prefix}-guardduty-portprobe"
  description = "Trigger auto-response on unprotected-port probe findings."
  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      type = [{ prefix = "Recon:EC2/PortProbeUnprotectedPort" }]
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.portprobe.name
  target_id = "lambda"
  arn       = aws_lambda_function.remediate.arn
}

resource "aws_lambda_permission" "events" {
  statement_id  = "AllowEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.portprobe.arn
}
