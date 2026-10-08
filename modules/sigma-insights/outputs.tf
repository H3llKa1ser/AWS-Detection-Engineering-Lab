output "saved_queries" {
  value = sort([for q in aws_cloudwatch_query_definition.sigma : q.name])
}

output "log_alarms" {
  value = sort([for a in awscc_cloudwatch_log_alarm.sigma : a.alarm_name])
}
