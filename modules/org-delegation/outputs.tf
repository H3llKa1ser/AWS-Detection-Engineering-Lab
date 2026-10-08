output "guardduty_delegated_regions" {
  value = sort(keys(aws_guardduty_organization_admin_account.this))
}

output "securityhub_delegated_admin" {
  value = aws_securityhub_organization_admin_account.this.admin_account_id
}
