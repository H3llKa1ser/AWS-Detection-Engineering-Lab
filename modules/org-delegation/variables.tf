variable "management_account_id" {
  description = "Account ID of the Organizations management account these resources are applied in."
  type        = string
}

variable "delegated_admin_account_id" {
  description = "Member account that administers GuardDuty and Security Hub for the organization (a dedicated security tooling account, never the management account)."
  type        = string
}

variable "home_region" {
  description = "Security Hub home region: central configuration and the finding aggregator live here."
  type        = string
}

variable "regions" {
  description = "Regions where GuardDuty runs organization-wide (must include home_region). GuardDuty delegation is per region."
  type        = list(string)
}

variable "enable_guardduty_trusted_access" {
  description = "Enable Organizations trusted access for GuardDuty with the AWS CLI. GuardDuty requires it before an API-designated delegated administrator; set false if your landing zone already manages trusted access."
  type        = bool
  default     = true
}
