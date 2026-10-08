terraform {
  required_version = ">= 1.9.0" # cross-variable validation rules (e.g. dns_firewall_block_override_domain)

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    external = {
      source  = "hashicorp/external"
      version = "~> 2.3"
    }
    awscc = {
      source  = "hashicorp/awscc"
      version = "~> 1.0" # CloudWatch log alarms (not yet in hashicorp/aws)
    }
  }
}
