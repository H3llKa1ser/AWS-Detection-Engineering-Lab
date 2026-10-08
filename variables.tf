variable "aws_region" {
  description = "Region to deploy the detection lab into. CloudTrail is multi-region regardless; this is the home region for log storage and regional services."
  type        = string
  default     = "eu-west-1"
}

variable "name_prefix" {
  description = "Short prefix applied to all resource names so the lab is easy to find and destroy."
  type        = string
  default     = "detlab"

  validation {
    condition     = can(regex("^[a-z0-9-]{2,20}$", var.name_prefix))
    error_message = "name_prefix must be 2-20 chars of lowercase letters, digits or hyphens."
  }
}

variable "log_retention_days" {
  description = "Retention for the CloudWatch Logs group that receives CloudTrail events."
  type        = number
  default     = 365
}

variable "alert_email" {
  description = "Optional email address subscribed to the alert SNS topic. Leave empty to wire your own subscription later. You must confirm the subscription from your inbox."
  type        = string
  default     = ""
}

variable "min_guardduty_severity" {
  description = "Minimum GuardDuty finding severity (numeric) that is forwarded to the alert topic. 1-3 low, 4-6 medium, 7-8.9 high."
  type        = number
  default     = 4
}

variable "enable_config" {
  description = "Deploy AWS Config recorder, delivery channel and a baseline set of managed rules."
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable the GuardDuty detector."
  type        = bool
  default     = true
}

variable "enable_securityhub" {
  description = "Enable Security Hub with the AWS Foundational and CIS standards."
  type        = bool
  default     = true
}

variable "enable_response_automation" {
  description = "Deploy the opt-in Lambda auto-response for GuardDuty findings. Off by default because it mutates resources (revokes offending security-group rules)."
  type        = bool
  default     = false
}

variable "kms_encrypt_logs" {
  description = "Create a customer-managed KMS key and use it to encrypt the CloudTrail log bucket and CloudWatch log group."
  type        = bool
  default     = true
}
