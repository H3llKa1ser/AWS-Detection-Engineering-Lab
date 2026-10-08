variable "name_prefix" { type = string }
variable "account_id" { type = string }
variable "partition" { type = string }

variable "hunts" {
  description = "Scheduled hunt => {named_query_id, title, attack} from the threat-hunting module."
  type = map(object({
    named_query_id = string
    title          = string
    attack         = string
  }))
}

variable "workgroup_name" { type = string }
variable "hunter_policy_arn" { type = string }
variable "alert_topic_arn" { type = string }

variable "schedule_hour" {
  description = "Hour of day (0-23) the daily run starts, in schedule_timezone."
  type        = number
  default     = 6
}

variable "schedule_timezone" {
  description = "IANA timezone for the schedule. UTC keeps every day exactly 24h, so the reporting windows never gap or overlap at DST changes."
  type        = string
  default     = "UTC"
}

variable "max_concurrency" {
  description = "Hunts run in parallel at most (Athena has per-account concurrency limits)."
  type        = number
  default     = 2
}

variable "sample_rows" {
  description = "Finding rows included in each alert (the full count is always included)."
  type        = number
  default     = 5
}
