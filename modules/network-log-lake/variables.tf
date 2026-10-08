variable "name_prefix" { type = string }
variable "account_id" { type = string }
variable "partition" { type = string }
variable "region" { type = string }

variable "bucket_name" {
  description = "Network log bucket name (computed in the root so other modules can reference it without a dependency cycle)."
  type        = string
}

variable "kms_key_arn" {
  type    = string
  default = null
}

variable "database_name" {
  description = "Glue database the tables are created in (the threat-hunting database)."
  type        = string
}

variable "enable_flow" { type = bool }
variable "enable_dns" { type = bool }

variable "projection_start" {
  type    = string
  default = "2025/01/01"
}

variable "retention_days" {
  description = "Days network logs are kept in S3."
  type        = number
  default     = 90
}

variable "firehose_buffer_seconds" {
  description = "Max seconds Firehose buffers DNS records before writing a Parquet file (60-900). Lower is fresher, but makes more small files."
  type        = number
  default     = 300
}
