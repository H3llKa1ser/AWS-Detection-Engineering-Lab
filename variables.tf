variable "aws_region" {
  description = "Region to deploy the detection lab into. CloudTrail is multi-region regardless; this is the home region for log storage and regional services."
  type        = string
  default     = "eu-west-1"
}

variable "name_prefix" {
  description = "Short prefix applied to all resource names so the lab is easy to find and destroy."
  type        = string
  default     = "detlab"

  validation {
    condition     = can(regex("^[a-z0-9-]{2,20}$", var.name_prefix))
    error_message = "name_prefix must be 2-20 chars of lowercase letters, digits or hyphens."
  }
}

variable "log_retention_days" {
  description = "Retention for the CloudWatch Logs group that receives CloudTrail events."
  type        = number
  default     = 365
}

variable "alert_email" {
  description = "Optional email address subscribed to the alert SNS topic. Leave empty to wire your own subscription later. You must confirm the subscription from your inbox."
  type        = string
  default     = ""
}

variable "min_guardduty_severity" {
  description = "Minimum GuardDuty finding severity (numeric) that is forwarded to the alert topic. 1-3 low, 4-6 medium, 7-8.9 high."
  type        = number
  default     = 4
}

variable "enable_config" {
  description = "Deploy AWS Config recorder, delivery channel and a baseline set of managed rules."
  type        = bool
  default     = true
}

variable "enable_guardduty" {
  description = "Enable the GuardDuty detector."
  type        = bool
  default     = true
}

variable "enable_securityhub" {
  description = "Enable Security Hub with the AWS Foundational and CIS standards."
  type        = bool
  default     = true
}

variable "enable_response_automation" {
  description = "Deploy the opt-in Lambda auto-response for GuardDuty findings. Off by default because it mutates resources (revokes offending security-group rules)."
  type        = bool
  default     = false
}

variable "kms_encrypt_logs" {
  description = "Create a customer-managed KMS key and use it to encrypt the CloudTrail log bucket and CloudWatch log group."
  type        = bool
  default     = true
}

# --- Network telemetry -------------------------------------------------------

variable "enable_vpc_flow_logs" {
  description = "Deploy VPC Flow Logs (to CloudWatch Logs) on the monitored VPCs, plus the flow-based detections."
  type        = bool
  default     = true
}

variable "enable_dns_query_logging" {
  description = "Deploy Route 53 Resolver query logging on the monitored VPCs, plus the DNS-based detections."
  type        = bool
  default     = true
}

variable "create_lab_vpc" {
  description = "Create an isolated lab VPC (no IGW/NAT, zero running cost) to attach network telemetry to."
  type        = bool
  default     = true
}

variable "lab_vpc_cidr" {
  description = "CIDR for the lab VPC."
  type        = string
  default     = "10.42.0.0/16"

  validation {
    condition     = can(cidrnetmask(var.lab_vpc_cidr))
    error_message = "lab_vpc_cidr must be a valid IPv4 CIDR block."
  }
}

variable "monitored_vpc_ids" {
  description = "Existing VPC ids to also attach flow logs and DNS query logging to. Flow-based detections need real traffic, so add a VPC with workloads here to exercise them."
  type        = list(string)
  default     = []

  validation {
    condition     = alltrue([for id in var.monitored_vpc_ids : can(regex("^vpc-[0-9a-f]+$", id))])
    error_message = "Every entry in monitored_vpc_ids must look like vpc-xxxxxxxx."
  }
}

variable "network_log_retention_days" {
  description = "Retention for the flow-log and DNS-query log groups. Kept shorter than CloudTrail because these are high volume."
  type        = number
  default     = 30
}

variable "deploy_traffic_generator" {
  description = "Launch a small hardened instance in the lab VPC that generates DNS traffic to exercise the DNS detections (and a real GuardDuty DNS finding). Costs one t3.micro while running."
  type        = bool
  default     = false
}

# --- DNS Firewall ------------------------------------------------------------

variable "enable_dns_firewall" {
  description = "Deploy Route 53 Resolver DNS Firewall with AWS-managed threat lists, plus the DNS Firewall detections."
  type        = bool
  default     = true
}

variable "dns_firewall_protect_monitored_vpcs" {
  description = "Also enforce DNS Firewall on monitored_vpc_ids. Off by default: blocking changes DNS answers for real workloads, so it is opt-in. The lab VPC is always protected when it exists."
  type        = bool
  default     = false
}

variable "dns_firewall_managed_lists" {
  description = "AWS-managed domain lists to enforce, in evaluation order. Specific lists first so logs attribute a match to its category; the aggregate list catches the rest. AWS recommends ALERT first in production, then BLOCK once evaluated."
  type = list(object({
    name   = string
    action = string
  }))
  default = [
    { name = "AWSManagedDomainsMalwareDomainList", action = "BLOCK" },
    { name = "AWSManagedDomainsBotnetCommandandControl", action = "BLOCK" },
    { name = "AWSManagedDomainsAggregateThreatList", action = "BLOCK" },
  ]

  validation {
    condition     = alltrue([for l in var.dns_firewall_managed_lists : contains(["BLOCK", "ALERT"], upper(l.action))])
    error_message = "Each managed list action must be BLOCK or ALERT."
  }
  validation {
    condition     = alltrue([for l in var.dns_firewall_managed_lists : startswith(l.name, "AWSManagedDomains")])
    error_message = "Managed list names start with AWSManagedDomains (e.g. AWSManagedDomainsAggregateThreatList)."
  }
  validation {
    condition     = length(distinct([for l in var.dns_firewall_managed_lists : l.name])) == length(var.dns_firewall_managed_lists)
    error_message = "Each managed list may appear only once."
  }
}

variable "dns_firewall_managed_list_ids" {
  description = "Optional name => id map for the managed lists. Lists named here skip the AWS CLI lookup; supply all of them to run without the AWS CLI (e.g. in CI)."
  type        = map(string)
  default     = {}
}

variable "dns_firewall_block_domains" {
  description = "Apex domains to always block (subdomains included). Defaults to the public cryptomining pools the dns_mining_pool_lookup detection watches for."
  type        = list(string)
  default     = ["nanopool.org", "supportxmr.com", "minexmr.com", "moneroocean.stream", "hashvault.pro"]
}

variable "dns_firewall_allow_domains" {
  description = "Apex domains always allowed (subdomains included), evaluated before every block rule. Use for confirmed false positives."
  type        = list(string)
  default     = []
}

variable "dns_firewall_block_response" {
  description = "Answer for blocked queries. NODATA (default) keeps rcode NOERROR, so blocks do not inflate the NXDOMAIN detection."
  type        = string
  default     = "NODATA"

  validation {
    condition     = contains(["NODATA", "NXDOMAIN", "OVERRIDE"], var.dns_firewall_block_response)
    error_message = "dns_firewall_block_response must be NODATA, NXDOMAIN or OVERRIDE."
  }
}

variable "dns_firewall_block_override_domain" {
  description = "Sinkhole domain returned as a CNAME when dns_firewall_block_response = OVERRIDE."
  type        = string
  default     = ""

  validation {
    condition     = var.dns_firewall_block_response != "OVERRIDE" || length(var.dns_firewall_block_override_domain) > 0
    error_message = "Set dns_firewall_block_override_domain when dns_firewall_block_response = OVERRIDE."
  }
}

variable "dns_firewall_fail_open" {
  description = "Behaviour if DNS Firewall cannot evaluate a query. false (fail closed) favours security; true favours availability."
  type        = bool
  default     = false
}

variable "dns_firewall_advanced_protections" {
  description = "DNS Firewall Advanced rules, evaluated after the managed lists. Confidence: LOW catches most with more false positives, HIGH only well-corroborated threats. For production, start with ALERT at LOW to see what you would catch, then BLOCK at MEDIUM or HIGH. Set to [] to disable."
  type = list(object({
    protection = string
    action     = string
    confidence = string
  }))
  default = [
    { protection = "DGA", action = "BLOCK", confidence = "MEDIUM" },
    { protection = "DICTIONARY_DGA", action = "BLOCK", confidence = "MEDIUM" },
    { protection = "DNS_TUNNELING", action = "BLOCK", confidence = "MEDIUM" },
  ]

  validation {
    condition     = alltrue([for a in var.dns_firewall_advanced_protections : contains(["DGA", "DICTIONARY_DGA", "DNS_TUNNELING"], upper(a.protection))])
    error_message = "protection must be DGA, DICTIONARY_DGA or DNS_TUNNELING."
  }
  validation {
    condition     = alltrue([for a in var.dns_firewall_advanced_protections : contains(["BLOCK", "ALERT"], upper(a.action))])
    error_message = "Advanced rules support BLOCK or ALERT only (ALLOW is not available for Advanced rules)."
  }
  validation {
    condition     = alltrue([for a in var.dns_firewall_advanced_protections : contains(["LOW", "MEDIUM", "HIGH"], upper(a.confidence))])
    error_message = "confidence must be LOW, MEDIUM or HIGH."
  }
  validation {
    condition     = length(distinct([for a in var.dns_firewall_advanced_protections : upper(a.protection)])) == length(var.dns_firewall_advanced_protections)
    error_message = "Each protection may appear only once."
  }
}

variable "dns_firewall_advanced_alarm_threshold" {
  description = "Newly flagged names per 5 minutes, per Advanced protection, before alarming."
  type        = number
  default     = 1
}

# --- Threat hunting (Athena) ---------------------------------------------------

variable "enable_threat_hunting" {
  description = "Deploy the Glue table over CloudTrail, the Athena hunting workgroup, saved hunts and the hunter IAM policy."
  type        = bool
  default     = true
}

variable "hunting_projection_start" {
  description = "Earliest day (yyyy/MM/dd) the CloudTrail table's partition projection considers."
  type        = string
  default     = "2025/01/01"

  validation {
    condition     = can(regex("^[0-9]{4}/[0-9]{2}/[0-9]{2}$", var.hunting_projection_start))
    error_message = "hunting_projection_start must be yyyy/MM/dd."
  }
}

variable "hunting_lookback_days" {
  description = "Hunting window baked into the saved queries (days). Bigger windows scan more data."
  type        = number
  default     = 30

  validation {
    condition     = var.hunting_lookback_days >= 2 && var.hunting_lookback_days <= 365
    error_message = "hunting_lookback_days must be between 2 and 365."
  }
}

variable "hunting_recent_days" {
  description = "'Recent' window for baseline-vs-recent hunts; the rest of the lookback is the baseline."
  type        = number
  default     = 1

  validation {
    condition     = var.hunting_recent_days >= 1
    error_message = "hunting_recent_days must be at least 1."
  }
}

variable "hunting_bytes_scanned_cutoff" {
  description = "Per-query scan cap enforced by the workgroup, in bytes (minimum 10 MB). Default 10 GiB."
  type        = number
  default     = 10737418240

  validation {
    condition     = var.hunting_bytes_scanned_cutoff >= 10485760
    error_message = "Athena's minimum per-query cutoff is 10 MB (10485760 bytes)."
  }
}
