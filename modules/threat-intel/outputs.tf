output "bucket_arn" {
  value = aws_s3_bucket.intel.arn
}

output "table" {
  value = aws_glue_catalog_table.indicators.name
}

output "indicators_by_source" {
  description = "Indicator counts per source in the applied set."
  value       = { for s in distinct([for r in local.rows : r.source]) : s => length([for r in local.rows : r if r.source == s]) }
}

output "content" {
  description = "The merged CSV exactly as uploaded (used by tests to check the renderer)."
  value       = local.content
}
