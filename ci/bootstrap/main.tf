# ---------------------------------------------------------------------------
# One-time bootstrap of a DEDICATED SANDBOX account for the live CI tiers.
# Apply once, by hand, with administrator credentials for that account:
#
#   terraform -chdir=ci/bootstrap init
#   terraform -chdir=ci/bootstrap apply -var budget_email=you@example.com
#
# then set the GitHub variables printed by `terraform output github_variables`
# on the repository's `sandbox` environment. Never point this at an account
# holding anything you care about: the CI role can create and delete almost
# everything in it.
# ---------------------------------------------------------------------------

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "detlab-ci", ManagedBy = "terraform" }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  account   = data.aws_caller_identity.current.account_id
  partition = data.aws_partition.current.partition
  oidc_host = "token.actions.githubusercontent.com"
  oidc_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : (
    "arn:${local.partition}:iam::${local.account}:oidc-provider/${local.oidc_host}"
  )
  role_name    = "detlab-ci-sandbox"
  state_bucket = "detlab-ci-tfstate-${local.account}-${var.region}"
  ci_bucket    = "detlab-ci-athena-${local.account}-${var.region}"
}

# --- GitHub OIDC ------------------------------------------------------------------
resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_oidc_provider ? 1 : 0
  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
    # Only jobs in this repository's `sandbox` environment (which can require
    # approval) may assume the role: not forks, not other branches' jobs
    # without the environment, not other repositories.
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${var.github_repository}:environment:${var.github_environment}"]
    }
  }
}

resource "aws_iam_role" "ci" {
  name                 = local.role_name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 10800 # the e2e tier runs for up to ~2.5 hours
}

resource "aws_iam_role_policy_attachment" "ci" {
  role       = aws_iam_role.ci.name
  policy_arn = var.ci_policy_arn
}

# Guardrails on top of the broad policy. Explicit denies win over any allow.
data "aws_iam_policy_document" "guardrails" {
  statement {
    sid       = "NoChangesToThisRoleOrItsTrust"
    effect    = "Deny"
    actions   = ["iam:*"]
    resources = [aws_iam_role.ci.arn, local.oidc_arn]
  }
  statement {
    sid    = "ProtectStateBucket"
    effect = "Deny"
    actions = [
      "s3:DeleteBucket", "s3:DeleteBucketPolicy", "s3:PutBucketPolicy", "s3:PutBucketVersioning",
      "s3:PutLifecycleConfiguration", "s3:PutBucketAcl", "s3:PutEncryptionConfiguration",
      "s3:DeleteObjectVersion", "s3:PutBucketObjectLockConfiguration",
    ]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]
  }
  statement {
    sid    = "StayInOneRegion"
    effect = "Deny"
    not_actions = [
      "iam:*", "sts:*", "organizations:Describe*", "organizations:List*", "support:*", "health:*",
      "budgets:*", "ce:*", "s3:ListAllMyBuckets", "s3:GetBucketLocation",
    ]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:RequestedRegion"
      values   = [var.region]
    }
  }
  statement {
    sid    = "NoAccountOrOrganizationChanges"
    effect = "Deny"
    actions = [
      "organizations:LeaveOrganization", "organizations:Create*", "organizations:Delete*",
      "organizations:Update*", "organizations:Invite*", "account:*",
      "iam:CreateAccountAlias", "iam:DeleteAccountAlias", "iam:UpdateAccountPasswordPolicy",
      "iam:DeleteAccountPasswordPolicy", "iam:CreateSAMLProvider", "iam:CreateOpenIDConnectProvider",
    ]
    resources = ["*"]
  }
  statement {
    sid    = "UsersAndKeysOnlyForE2eTargets"
    effect = "Deny"
    actions = ["iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:AddUserToGroup"]
    not_resources = ["arn:${local.partition}:iam::${local.account}:user/e2e-*"]
  }
}

resource "aws_iam_role_policy" "guardrails" {
  name   = "guardrails"
  role   = aws_iam_role.ci.id
  policy = data.aws_iam_policy_document.guardrails.json
}

# --- Terraform state for e2e runs -------------------------------------------------------
resource "aws_s3_bucket" "state" {
  bucket = local.state_bucket
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id
  rule {
    id     = "expire-old-state-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = 90 }
  }
}

data "aws_iam_policy_document" "tls_only" {
  for_each = { state = aws_s3_bucket.state.arn, ci = aws_s3_bucket.ci.arn }
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [each.value, "${each.value}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.tls_only["state"].json
}

# --- Athena workgroup for the conformance tier -------------------------------------------------
resource "aws_s3_bucket" "ci" {
  bucket        = local.ci_bucket
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "ci" {
  bucket                  = aws_s3_bucket.ci.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ci" {
  bucket = aws_s3_bucket.ci.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "ci" {
  bucket = aws_s3_bucket.ci.id
  rule {
    id     = "expire-results"
    status = "Enabled"
    filter {}
    expiration { days = 7 }
  }
}

resource "aws_s3_bucket_policy" "ci" {
  bucket = aws_s3_bucket.ci.id
  policy = data.aws_iam_policy_document.tls_only["ci"].json
}

resource "aws_athena_workgroup" "conformance" {
  name          = "detlab-ci-conformance"
  force_destroy = true
  configuration {
    enforce_workgroup_configuration = true
    bytes_scanned_cutoff_per_query  = 1073741824 # 1 GiB; conformance queries scan nothing
    engine_version {
      selected_engine_version = "Athena engine version 3"
    }
    result_configuration {
      output_location = "s3://${aws_s3_bucket.ci.bucket}/results/"
      encryption_configuration { encryption_option = "SSE_S3" }
    }
  }
}

# --- Cost guard -----------------------------------------------------------------------------------------
resource "aws_budgets_budget" "sandbox" {
  count        = var.budget_email == "" ? 0 : 1
  name         = "detlab-ci-sandbox-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_budget_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"

  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 80
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_email]
  }
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "FORECASTED"
    subscriber_email_addresses = [var.budget_email]
  }
}
