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
