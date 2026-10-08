output "database" {
  value = aws_glue_catalog_database.security.name
}

output "table" {
  value = "${aws_glue_catalog_database.security.name}.${aws_glue_catalog_table.cloudtrail.name}"
}

output "workgroup" {
  value = aws_athena_workgroup.hunting.name
}

output "results_bucket" {
  value = aws_s3_bucket.results.bucket
}

output "hunter_policy_arn" {
  value = aws_iam_policy.hunter.arn
}

output "saved_hunts" {
  description = "Saved query name => ATT&CK mapping."
  value       = { for k, q in local.deployable : "${k}: ${q.title}" => q.attack }
}

output "scheduled_hunts" {
  description = "Scheduled hunt => {named_query_id, title, attack}, for the scheduler."
  value = { for k, q in aws_athena_named_query.scheduled : k => {
    named_query_id = q.id
    title          = local.scheduled[k].title
    attack         = local.scheduled[k].attack
  } }
}

output "workgroup_arn" {
  value = aws_athena_workgroup.hunting.arn
}

output "schedulable_hunts" {
  value = sort(keys(local.schedulable))
}

output "retro_hunts" {
  description = "Retro-hunt variants of the intel hunts, re-run whenever the indicator set changes."
  value = { for k, q in aws_athena_named_query.retro : k => {
    named_query_id = q.id
    title          = local.retro[k].title
    attack         = local.retro[k].attack
  } }
}
