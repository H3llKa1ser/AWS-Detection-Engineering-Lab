output "state_machine_arn" {
  value = aws_sfn_state_machine.hunts.arn
}

output "schedule" {
  value = "daily at ${format("%02d", var.schedule_hour)}:00 ${var.schedule_timezone}: ${join(", ", sort(keys(var.hunts)))}"
}

output "run_now" {
  description = "Run the scheduled hunts immediately, with the exact input the schedule uses."
  value       = "aws stepfunctions start-execution --state-machine-arn ${aws_sfn_state_machine.hunts.arn} --input '${local.input}'"
}
