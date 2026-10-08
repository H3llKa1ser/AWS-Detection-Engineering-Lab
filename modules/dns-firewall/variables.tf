variable "name_prefix" { type = string }
variable "region" { type = string }

variable "vpc_ids" {
  description = "Map of stable key => VPC id to protect with DNS Firewall."
  type        = map(string)
}

variable "managed_domain_lists" {
  description = "AWS-managed domain lists to enforce, in evaluation order, each with its action (BLOCK or ALERT)."
  type = list(object({
    name   = string
    action = string
  }))
}

variable "managed_domain_list_ids" {
  description = "Optional name => id overrides for the managed lists. Any list named here skips the AWS CLI lookup."
  type        = map(string)
  default     = {}
}

variable "block_domains" {
  description = "Apex domains to block (each also blocks its subdomains)."
  type        = list(string)
  default     = []
}

variable "allow_domains" {
  description = "Apex domains always allowed, evaluated before every block rule (false-positive overrides). Each also covers its subdomains."
  type        = list(string)
  default     = []
}

variable "block_response" {
  description = "Answer returned for blocked queries: NODATA, NXDOMAIN or OVERRIDE."
  type        = string
  default     = "NODATA"
}

variable "block_override_domain" {
  description = "Sinkhole domain returned as a CNAME when block_response = OVERRIDE."
  type        = string
  default     = ""
}

variable "fail_open" {
  description = "If DNS Firewall cannot evaluate a query: true lets it through (availability), false blocks it (security)."
  type        = bool
  default     = false
}

variable "association_priority" {
  description = "Priority of this rule group among rule groups associated with each VPC (101-9899, lower runs first)."
  type        = number
  default     = 200
}

# --- DNS Firewall Advanced -----------------------------------------------------

variable "advanced_protections" {
  description = "DNS Firewall Advanced rules (no domain list): protection DGA | DICTIONARY_DGA | DNS_TUNNELING, action BLOCK | ALERT, confidence LOW | MEDIUM | HIGH."
  type = list(object({
    protection = string
    action     = string
    confidence = string
  }))
  default = []
}

variable "alert_topic_arn" {
  description = "SNS topic for Advanced verdict alarms."
  type        = string
}

variable "advanced_alarm_threshold" {
  description = "Advanced verdict events per 5 minutes before alarming. Each event is a newly flagged name (DNS Firewall sends one per domain per 6 hours)."
  type        = number
  default     = 1
}

variable "account_id" { type = string }
variable "partition" { type = string }

variable "kms_key_arn" {
  type    = string
  default = null
}

variable "event_log_retention_days" {
  type    = number
  default = 90
}
