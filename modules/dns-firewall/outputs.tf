output "rule_group_id" {
  value = aws_route53_resolver_firewall_rule_group.main.id
}

output "rules" {
  description = "Effective rule order: priority => action and domain list."
  value = merge(
    { for r in aws_route53_resolver_firewall_rule.allow : tostring(r.priority) => "ALLOW custom allowlist" },
    { for r in aws_route53_resolver_firewall_rule.block : tostring(r.priority) => "BLOCK custom blocklist" },
    { for name, r in aws_route53_resolver_firewall_rule.managed : tostring(r.priority) => "${r.action} ${name}" },
    { for p, r in aws_route53_resolver_firewall_rule.advanced : tostring(r.priority) => "${r.action} Advanced ${p} @ ${r.confidence_threshold}" },
  )
}

output "managed_domain_list_ids" {
  description = "Resolved IDs of the managed lists in use (handy for reading firewall_domain_list_id in logs)."
  value       = { for name, d in data.aws_route53_resolver_firewall_domain_list.managed : name => d.firewall_domain_list_id }
}

output "advanced_alarm_names" {
  value = [for a in aws_cloudwatch_metric_alarm.advanced : a.alarm_name]
}

output "advanced_event_log_group" {
  value = length(aws_cloudwatch_log_group.advanced_events) > 0 ? aws_cloudwatch_log_group.advanced_events[0].name : null
}
