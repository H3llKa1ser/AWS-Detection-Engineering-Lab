variable "name_prefix" { type = string }
variable "account_id" { type = string }
variable "partition" { type = string }
variable "region" { type = string }

variable "vpc_ids" {
  description = "Map of stable key => VPC id whose Route 53 Resolver queries are logged."
  type        = map(string)
}

variable "log_retention_days" { type = number }

variable "kms_key_arn" {
  type    = string
  default = null
}
