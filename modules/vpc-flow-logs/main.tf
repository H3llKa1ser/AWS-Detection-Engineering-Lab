# ---------------------------------------------------------------------------
# VPC Flow Logs -> CloudWatch Logs
#
# Uses a custom version-5 log format. The first 14 fields are the AWS default
# format in the default order (so standard tooling still understands them);
# the extra fields add VPC/subnet/instance context, TCP flags and, critically,
# flow-direction, which lets detections distinguish inbound from outbound.
#
# The field order here is a contract with the detection catalogue
# (modules/detections/catalogue_network.tf -> local.flow_fields). Change one,
# change both.
# ---------------------------------------------------------------------------

locals {
  log_group_name = "/${var.name_prefix}/vpc-flow-logs"

  log_format = join(" ", [
    "$${version}", "$${account-id}", "$${interface-id}", "$${srcaddr}", "$${dstaddr}",
    "$${srcport}", "$${dstport}", "$${protocol}", "$${packets}", "$${bytes}",
    "$${start}", "$${end}", "$${action}", "$${log-status}",
    "$${vpc-id}", "$${subnet-id}", "$${instance-id}", "$${tcp-flags}", "$${type}",
    "$${pkt-srcaddr}", "$${pkt-dstaddr}", "$${flow-direction}",
  ])
}

resource "aws_cloudwatch_log_group" "flow" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
    # Confused-deputy protection: only flow logs in this account may assume.
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${var.partition}:ec2:${var.region}:${var.account_id}:vpc-flow-log/*"]
    }
  }
}

resource "aws_iam_role" "flow" {
  name               = "${var.name_prefix}-vpc-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "flow" {
  statement {
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = [aws_cloudwatch_log_group.flow.arn, "${aws_cloudwatch_log_group.flow.arn}:*"]
  }
}

resource "aws_iam_role_policy" "flow" {
  name   = "${var.name_prefix}-vpc-flow-logs"
  role   = aws_iam_role.flow.id
  policy = data.aws_iam_policy_document.flow.json
}

resource "aws_flow_log" "vpc" {
  for_each = var.vpc_ids

  vpc_id                   = each.value
  traffic_type             = var.traffic_type
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow.arn
  iam_role_arn             = aws_iam_role.flow.arn
  log_format               = local.log_format
  max_aggregation_interval = 60 # 1-minute records: faster detection, same cost per GB

  tags = { Name = "${var.name_prefix}-flow-${each.key}" }
}
