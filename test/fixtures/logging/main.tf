module "logging" {
  source = "../../../modules/logging"

  name_prefix        = var.name_prefix
  log_retention_days = 1
  kms_encrypt_logs   = true
  account_id         = local.account_id
  partition          = local.partition
  region             = var.region
}

output "bucket" { value = module.logging.cloudtrail_bucket_name }
output "log_group" { value = module.logging.cloudwatch_log_group_name }
output "kms_key_arn" { value = module.logging.kms_key_arn }
output "trail" { value = module.logging.cloudtrail_name }
