output "config_bucket_name" {
  value = aws_s3_bucket.config.id
}

output "config_rule_names" {
  value = [for r in aws_config_config_rule.managed : r.name]
}
