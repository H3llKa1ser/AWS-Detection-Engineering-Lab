output "guardduty_detector_id" {
  value = var.enable_guardduty ? aws_guardduty_detector.main[0].id : null
}

output "securityhub_enabled" {
  value = var.enable_securityhub
}
