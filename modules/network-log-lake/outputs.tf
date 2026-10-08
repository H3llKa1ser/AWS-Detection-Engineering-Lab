output "bucket_arn" {
  value = aws_s3_bucket.network.arn
  # AWS checks delivery permissions when a flow log is created, so consumers
  # must not see this ARN before the bucket policy exists.
  depends_on = [aws_s3_bucket_policy.network]
}

output "firehose_arn" {
  value = var.enable_dns ? aws_kinesis_firehose_delivery_stream.dns[0].arn : null
}

output "flow_table" {
  value = var.enable_flow ? aws_glue_catalog_table.flow[0].name : null
}

output "dns_table" {
  value = var.enable_dns ? aws_glue_catalog_table.dns[0].name : null
}
