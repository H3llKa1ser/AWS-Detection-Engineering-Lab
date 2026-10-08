variable "home_region" {
  description = "Security Hub home region: central configuration and the finding aggregator."
  type        = string
  default     = "eu-west-1"
}

variable "regions" {
  description = "Regions covered organization-wide. Must include home_region."
  type        = list(string)
  default     = ["eu-west-1"]

  validation {
    condition     = length(var.regions) > 0 && length(distinct(var.regions)) == length(var.regions)
    error_message = "regions must be a non-empty list without duplicates."
  }
  validation {
    condition     = contains(var.regions, var.home_region)
    error_message = "regions must include home_region."
  }
  validation {
    condition     = alltrue([for r in var.regions : can(regex("^[a-z]{2}(-gov)?-[a-z]+-[0-9]$", r))])
    error_message = "Each region must look like eu-west-1."
  }
}

variable "delegated_admin_account_id" {
  description = "Security tooling member account that administers GuardDuty and Security Hub."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.delegated_admin_account_id))
    error_message = "delegated_admin_account_id must be a 12-digit account ID."
  }
}

variable "management_account_id" {
  description = "Organizations management account ID (where this root is applied)."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "management_account_id must be a 12-digit account ID."
  }
  validation {
    condition     = var.management_account_id != var.delegated_admin_account_id
    error_message = "Delegate to a member account: AWS requires it for Security Hub central configuration and recommends it for GuardDuty."
  }
}

variable "enable_guardduty_trusted_access" {
  description = "Enable Organizations trusted access for GuardDuty via the AWS CLI (false if your landing zone manages it)."
  type        = bool
  default     = true
}
