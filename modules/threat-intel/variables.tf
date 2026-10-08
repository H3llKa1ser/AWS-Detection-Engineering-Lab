variable "name_prefix" { type = string }
variable "account_id" { type = string }
variable "partition" { type = string }
variable "region" { type = string }

variable "bucket_name" {
  description = "Intel bucket name (computed in the root so other modules can reference it without a cycle)."
  type        = string
}

variable "kms_key_arn" {
  type    = string
  default = null
}

variable "database_name" {
  description = "Glue database for the indicator table (the threat-hunting database)."
  type        = string
}

variable "indicator_dir" {
  description = "Directory of curated *.csv indicator files."
  type        = string
}
