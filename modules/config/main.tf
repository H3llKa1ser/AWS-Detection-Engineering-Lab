# ---------------------------------------------------------------------------
# AWS Config: record resource configuration history and continuously evaluate
# a baseline of managed rules. Config findings feed Security Hub automatically.
# ---------------------------------------------------------------------------

locals {
  bucket_name = "${var.name_prefix}-config-${var.account_id}"
  managed_rules = {
    s3-public-read-prohibited  = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
    s3-public-write-prohibited = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
    s3-ssl-requests-only       = "S3_BUCKET_SSL_REQUESTS_ONLY"
    iam-root-mfa-enabled       = "ROOT_ACCOUNT_MFA_ENABLED"
    iam-user-mfa-enabled       = "IAM_USER_MFA_ENABLED"
    iam-no-inline-policy       = "IAM_NO_INLINE_POLICY_CHECK"
    ebs-encryption-by-default  = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
    cloudtrail-enabled         = "CLOUD_TRAIL_ENABLED"
    vpc-default-sg-closed      = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
    restricted-ssh             = "INCOMING_SSH_DISABLED"
  }
}

resource "aws_s3_bucket" "config" {
  bucket        = local.bucket_name
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "config_bucket" {
  statement {
    sid     = "AWSConfigBucketPermissionsCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = [aws_s3_bucket.config.arn]
  }
  statement {
    sid     = "AWSConfigBucketDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${var.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = data.aws_iam_policy_document.config_bucket.json
}

data "aws_iam_policy_document" "config_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config" {
  name               = "${var.name_prefix}-config-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:${var.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config.arn
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = aws_s3_bucket.config.id
  depends_on     = [aws_config_configuration_recorder.main, aws_s3_bucket_policy.config]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_config_rule" "managed" {
  for_each = local.managed_rules

  name = "${var.name_prefix}-${each.key}"
  source {
    owner             = "AWS"
    source_identifier = each.value
  }
  depends_on = [aws_config_configuration_recorder.main]
}
