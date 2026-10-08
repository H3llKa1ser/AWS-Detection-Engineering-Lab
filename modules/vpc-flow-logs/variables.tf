variable "name_prefix" { type = string }
variable "account_id" { type = string }
variable "partition" { type = string }
variable "region" { type = string }

variable "vpc_ids" {
  description = "Map of stable key => VPC id to attach flow logs to. Keys must be known at plan time; values may be computed."
  type        = map(string)
}

variable "log_retention_days" { type = number }

variable "kms_key_arn" {
  type    = string
  default = null
}

variable "traffic_type" {
  description = "ACCEPT, REJECT or ALL. Detections need ALL (egress-accept and ingress-reject both matter)."
  type        = string
  default     = "ALL"
}
