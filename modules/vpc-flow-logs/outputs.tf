output "log_group_name" {
  value = aws_cloudwatch_log_group.flow.name
}

output "log_format" {
  value = local.log_format
}

output "flow_log_ids" {
  value = { for k, v in aws_flow_log.vpc : k => v.id }
}
