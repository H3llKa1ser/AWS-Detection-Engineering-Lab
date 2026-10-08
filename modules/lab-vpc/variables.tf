variable "name_prefix" { type = string }
variable "cidr_block" { type = string }

variable "enable_ipv6" {
  description = "Give the lab VPC an Amazon-provided IPv6 /56 (free), so IPv6-aware hunts have a real VPC range to work with."
  type        = bool
  default     = true
}
