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

variable "enable_s3_parquet" {
  description = "Also deliver flow logs to S3 as Parquet for Athena hunting. This is a second flow log per VPC: AWS allows 2 per VPC, so a monitored VPC that already has one elsewhere will fail."
  type        = bool
  default     = false
}

variable "s3_bucket_arn" {
  type    = string
  default = null
}
