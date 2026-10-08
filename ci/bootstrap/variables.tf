variable "region" {
  description = "The one region the CI role may act in (global services excepted)."
  type        = string
  default     = "eu-west-1"
}

variable "github_repository" {
  description = "owner/name of the repository whose `sandbox` environment may assume the CI role."
  type        = string
  default     = "H3llKa1ser/AWS-Detection-Engineering-Lab"
}

variable "github_environment" {
  type    = string
  default = "sandbox"
}

variable "create_oidc_provider" {
  description = "Create the GitHub OIDC provider (false if the account already has one)."
  type        = bool
  default     = true
}

variable "ci_policy_arn" {
  description = "Managed policy for the CI role. Broad because the lab creates most resource types; contained by the guardrail denies and by the account being a dedicated sandbox."
  type        = string
  default     = "arn:aws:iam::aws:policy/AdministratorAccess"
}

variable "budget_email" {
  description = "Email for budget alerts (80% actual, 100% forecast). Empty disables the budget."
  type        = string
  default     = ""
}

variable "monthly_budget_usd" {
  type    = number
  default = 25
}
