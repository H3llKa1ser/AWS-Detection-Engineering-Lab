# ---------------------------------------------------------------------------
# Route 53 Resolver query logging -> CloudWatch Logs
#
# Logs every DNS query that resources in the associated VPCs send to the
# Route 53 Resolver: query name and type, response code, answers, and the
# source instance. Records are JSON, so detections use JSON metric filters.
# ---------------------------------------------------------------------------

locals {
  log_group_name = "/${var.name_prefix}/route53-resolver-queries"
}

resource "aws_cloudwatch_log_group" "dns" {
  name              = local.log_group_name
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_arn
}

# Resolver delivers through the CloudWatch Logs "vended logs" path. AWS will
# try to create this resource policy itself if the caller has permission; we
# declare it explicitly so the deployment is deterministic and least-privilege.
data "aws_iam_policy_document" "delivery" {
  statement {
    sid     = "Route53ResolverQueryLogDelivery"
    effect  = "Allow"
    actions = ["logs:CreateLogStream", "logs:PutLogEvents"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    resources = ["${aws_cloudwatch_log_group.dns.arn}:*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${var.partition}:logs:${var.region}:${var.account_id}:*"]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "dns" {
  policy_name     = "${var.name_prefix}-route53-resolver-query-logs"
  policy_document = data.aws_iam_policy_document.delivery.json
}

resource "aws_route53_resolver_query_log_config" "main" {
  name            = "${var.name_prefix}-dns-query-logs"
  destination_arn = aws_cloudwatch_log_group.dns.arn

  depends_on = [aws_cloudwatch_log_resource_policy.dns]
}

resource "aws_route53_resolver_query_log_config_association" "vpc" {
  for_each = var.vpc_ids

  resolver_query_log_config_id = aws_route53_resolver_query_log_config.main.id
  resource_id                  = each.value
}
