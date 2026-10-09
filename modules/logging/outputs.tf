output "cloudtrail_bucket_name" {
  value = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_bucket_arn" {
  value = aws_s3_bucket.cloudtrail.arn
}

output "cloudwatch_log_group_name" {
  value = aws_cloudwatch_log_group.trail.name
}

output "kms_key_arn" {
  value = var.kms_encrypt_logs ? aws_kms_key.logs[0].arn : null
}

output "cloudtrail_name" {
  value = aws_cloudtrail.main.name
}
