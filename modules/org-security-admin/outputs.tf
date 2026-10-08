output "guardduty_detectors" {
  value = { for r, d in aws_guardduty_detector.admin : r => d.id }
}

output "securityhub_policy_id" {
  value = aws_securityhub_configuration_policy.org.id
}

output "linked_regions" {
  value = local.linked_regions
}
