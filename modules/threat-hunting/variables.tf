variable "name_prefix" { type = string }
variable "account_id" { type = string }
variable "partition" { type = string }
variable "region" { type = string }

variable "cloudtrail_bucket_name" { type = string }
variable "cloudtrail_bucket_arn" { type = string }

variable "kms_key_arn" {
  description = "Lab CMK. Used to read SSE-KMS CloudTrail objects and to encrypt query results. Null means SSE-S3."
  type        = string
  default     = null
}

variable "projection_start" {
  description = "Earliest day (yyyy/MM/dd) partition projection will consider. Older than your oldest log is harmless; queries prune by date anyway."
  type        = string
  default     = "2025/01/01"
}

variable "lookback_days" {
  description = "Default hunting window baked into the saved queries."
  type        = number
  default     = 30
}

variable "recent_days" {
  description = "'Recent' window for baseline-vs-recent hunts (new region, new login source, new role assumer)."
  type        = number
  default     = 1
}

variable "bytes_scanned_cutoff" {
  description = "Per-query scan limit enforced by the workgroup (bytes). Queries that would scan more are cancelled."
  type        = number
  default     = 10737418240 # 10 GiB
}

variable "results_retention_days" {
  type    = number
  default = 30
}
