# Renders the detection catalogue's metric-filter patterns WITHOUT AWS access:
# `terraform plan` on just the detections module, with credential checks
# skipped, yields every pattern as a planned value. Used by CI to test the
# patterns against the real CloudWatch TestMetricFilter API (tests/live/).
#
#   terraform -chdir=ci/render-catalogue init
#   terraform -chdir=ci/render-catalogue plan -out=plan.bin
#   terraform -chdir=ci/render-catalogue show -json plan.bin > catalogue-plan.json

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region                      = "eu-west-1"
  access_key                  = "render-only"
  secret_key                  = "render-only"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}

module "detections" {
  source = "../../modules/detections"

  name_prefix         = "render"
  alarm_sns_topic_arn = "arn:aws:sns:eu-west-1:111122223333:render"
  enabled_sources     = ["cloudtrail", "vpc_flow", "dns", "dns_firewall"]
  log_groups = {
    cloudtrail   = "/render/cloudtrail"
    vpc_flow     = "/render/vpc-flow-logs"
    dns          = "/render/dns"
    dns_firewall = "/render/dns"
  }
}
