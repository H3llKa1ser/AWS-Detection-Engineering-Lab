variable "home_region" {
  description = "Security Hub home region (where the delegated administrator was designated)."
  type        = string
}

variable "regions" {
  description = "Regions covered organization-wide; must include home_region."
  type        = list(string)
}

variable "partition" {
  type    = string
  default = "aws"
}

variable "auto_enable_members" {
  description = "GuardDuty for member accounts: ALL (existing and new), NEW (only accounts that join later) or NONE."
  type        = string
  default     = "ALL"
}

variable "guardduty_features" {
  description = "GuardDuty protection plans and their organization auto-enable setting (ALL, NEW or NONE). Defaults keep cost predictable: runtime, EKS, RDS and Lambda monitoring bill per resource across every account."
  type        = map(string)
  default = {
    S3_DATA_EVENTS         = "ALL"
    EBS_MALWARE_PROTECTION = "ALL"
    RDS_LOGIN_EVENTS       = "NONE"
    EKS_AUDIT_LOGS         = "NONE"
    RUNTIME_MONITORING     = "NONE"
    LAMBDA_NETWORK_LOGS    = "NONE"
  }
}

variable "securityhub_standards" {
  description = "Standards enabled by the central configuration policy, as standards/<path> suffixes."
  type        = list(string)
  default = [
    "aws-foundational-security-best-practices/v/1.0.0",
    "cis-aws-foundations-benchmark/v/1.4.0",
  ]
}

variable "securityhub_disabled_controls" {
  description = "Security Hub control IDs disabled organization-wide (e.g. controls that do not apply to you), with the reason in your change history."
  type        = list(string)
  default     = []
}

variable "policy_targets" {
  description = "Where the configuration policy applies: the organization root (r-...), OUs (ou-...) or accounts."
  type        = list(string)
}
