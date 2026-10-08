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

variable "name_prefix" {
  type    = string
  default = "org-security"
}

variable "partition" {
  type    = string
  default = "aws"
}

variable "alert_email" {
  type    = string
  default = ""
}

variable "min_guardduty_severity" {
  type    = number
  default = 7
}

variable "auto_enable_members" {
  description = "GuardDuty for member accounts: ALL, NEW or NONE."
  type        = string
  default     = "ALL"

  validation {
    condition     = contains(["ALL", "NEW", "NONE"], var.auto_enable_members)
    error_message = "auto_enable_members must be ALL, NEW or NONE."
  }
}

variable "guardduty_features" {
  description = "GuardDuty protection plan => organization auto-enable (ALL, NEW, NONE)."
  type        = map(string)
  default = {
    S3_DATA_EVENTS         = "ALL"
    EBS_MALWARE_PROTECTION = "ALL"
    RDS_LOGIN_EVENTS       = "NONE"
    EKS_AUDIT_LOGS         = "NONE"
    RUNTIME_MONITORING     = "NONE"
    LAMBDA_NETWORK_LOGS    = "NONE"
  }

  validation {
    condition = alltrue([for k in keys(var.guardduty_features) : contains([
      "S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "EBS_MALWARE_PROTECTION", "RDS_LOGIN_EVENTS", "LAMBDA_NETWORK_LOGS",
    "EKS_RUNTIME_MONITORING", "RUNTIME_MONITORING", "AI_PROTECTION"], k)])
    error_message = "Unknown GuardDuty feature name (see the GuardDuty UpdateOrganizationConfiguration API)."
  }
  validation {
    condition     = alltrue([for v in values(var.guardduty_features) : contains(["ALL", "NEW", "NONE"], v)])
    error_message = "Feature auto-enable values must be ALL, NEW or NONE."
  }
}

variable "securityhub_standards" {
  type = list(string)
  default = [
    "aws-foundational-security-best-practices/v/1.0.0",
    "cis-aws-foundations-benchmark/v/1.4.0",
  ]

  validation {
    condition     = alltrue([for s in var.securityhub_standards : can(regex("^[a-z0-9-]+/v/[0-9.]+$", s))])
    error_message = "Standards are written as <name>/v/<version>, e.g. aws-foundational-security-best-practices/v/1.0.0."
  }
}

variable "securityhub_disabled_controls" {
  type    = list(string)
  default = []
}

variable "policy_targets" {
  description = "Organization root (r-...), OUs (ou-...) or account IDs the configuration policy applies to."
  type        = list(string)

  validation {
    condition = length(var.policy_targets) > 0 && alltrue([for t in var.policy_targets :
    can(regex("^(r-[0-9a-z]{4,32}|ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}|[0-9]{12})$", t))])
    error_message = "policy_targets must be a non-empty list of r-..., ou-... or 12-digit account IDs."
  }
}
