# Shared by every Terratest fixture: `offline = true` plans with faked
# credentials and makes no AWS calls (unit tier); false applies for real
# (integration tier, sandbox account).

variable "offline" {
  type    = bool
  default = false
}

variable "name_prefix" {
  type = string
}

variable "region" {
  type    = string
  default = "eu-west-1"
}

provider "aws" {
  region                      = var.region
  access_key                  = var.offline ? "unit-test" : null
  secret_key                  = var.offline ? "unit-test" : null
  skip_credentials_validation = var.offline
  skip_requesting_account_id  = var.offline
  skip_metadata_api_check     = var.offline

  default_tags {
    tags = { Project = var.name_prefix, Purpose = "terratest" }
  }
}

data "aws_caller_identity" "current" {
  count = var.offline ? 0 : 1
}

locals {
  account_id = var.offline ? "111122223333" : data.aws_caller_identity.current[0].account_id
  partition  = "aws"
}
