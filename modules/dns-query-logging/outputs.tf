output "log_group_name" {
  value = aws_cloudwatch_log_group.dns.name
}

output "query_log_config_id" {
  value = aws_route53_resolver_query_log_config.main.id
}
