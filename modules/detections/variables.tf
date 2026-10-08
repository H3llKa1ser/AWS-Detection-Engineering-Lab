variable "name_prefix" { type = string }
variable "alarm_sns_topic_arn" { type = string }

variable "log_groups" {
  description = "Map of telemetry source => CloudWatch Logs group name (cloudtrail, vpc_flow, dns)."
  type        = map(string)
}

variable "enabled_sources" {
  description = "Telemetry sources that are deployed. Detections for any other source are skipped. Must be known at plan time."
  type        = list(string)
}

variable "extra_detections" {
  description = "Additional catalogue entries, e.g. metric filters generated from Sigma rules (sigma/generated/metric_filters.json)."
  type = map(object({
    source      = string
    description = string
    attack      = string
    threshold   = number
    pattern     = string
  }))
  default = {}
}
