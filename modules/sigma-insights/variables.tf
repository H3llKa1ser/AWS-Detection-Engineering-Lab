variable "name_prefix" { type = string }
variable "account_id" { type = string }
variable "partition" { type = string }
variable "region" { type = string }

variable "log_group_name" {
  description = "CloudTrail log group the queries run over."
  type        = string
}

variable "kms_key_arn" {
  type    = string
  default = null
}

variable "alert_topic_arn" { type = string }

variable "rules" {
  description = "Converted rules from sigma/generated/insights_queries.json."
  type = map(object({
    title       = string
    level       = string
    attack      = string
    saved_query = string
    alarm_query = string
  }))
}

variable "enable_alarms" {
  description = "Create log alarms (scheduled queries that alert). Saved queries are always created."
  type        = bool
  default     = true
}

variable "schedule_minutes" {
  description = "How often each log alarm runs its query."
  type        = number
  default     = 5
}

variable "lookback_minutes" {
  description = "Window each run searches. Longer than the schedule so events delivered late to CloudWatch Logs are still seen; an event can then be counted by up to lookback/schedule consecutive runs."
  type        = number
  default     = 15
}
