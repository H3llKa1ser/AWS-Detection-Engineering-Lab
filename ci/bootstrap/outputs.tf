output "github_variables" {
  description = "Set these as variables on the repository's `sandbox` environment."
  value = {
    AWS_SANDBOX_ROLE_ARN     = aws_iam_role.ci.arn
    AWS_SANDBOX_REGION       = var.region
    AWS_SANDBOX_STATE_BUCKET = aws_s3_bucket.state.bucket
    AWS_SANDBOX_CI_WORKGROUP = aws_athena_workgroup.conformance.name
  }
}
