# Sigma rules as Logs Insights saved queries and log alarms, on a stand-in
# CloudTrail log group the tests write events into.
variable "rules" {
  type    = list(string)
  default = ["sigma_ssm_command_by_human"]
}

variable "enable_alarms" {
  type    = bool
  default = true
}

# awscc validates credentials with STS whenever it is configured (no skip
# option), so this fixture is integration-only.
provider "awscc" {
  region = var.region
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/${var.name_prefix}/terratest/cloudtrail"
  retention_in_days = 1
}

resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-alerts"
}

module "sigma_insights" {
  source = "../../../modules/sigma-insights"

  name_prefix     = var.name_prefix
  account_id      = local.account_id
  partition       = local.partition
  region          = var.region
  log_group_name  = aws_cloudwatch_log_group.cloudtrail.name
  alert_topic_arn = aws_sns_topic.alerts.arn
  enable_alarms   = var.enable_alarms
  rules = { for k, v in jsondecode(file("${path.module}/../../../sigma/generated/insights_queries.json")) :
  k => v if contains(var.rules, k) }
}

output "log_group" { value = aws_cloudwatch_log_group.cloudtrail.name }
output "log_alarms" { value = module.sigma_insights.log_alarms }
output "saved_queries" { value = module.sigma_insights.saved_queries }
