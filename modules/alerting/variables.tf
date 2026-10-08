variable "name_prefix" { type = string }
variable "alert_email" { type = string }
variable "min_guardduty_severity" { type = number }
variable "enable_guardduty" { type = bool }
variable "enable_securityhub" { type = bool }
variable "account_id" { type = string }
variable "partition" { type = string }
variable "region" { type = string }
