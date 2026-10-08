output "detection_names" {
  value = keys(local.active_detections)
}

output "detection_count" {
  value = length(local.active_detections)
}

output "detections_by_source" {
  value = {
    for src in distinct([for d in local.active_detections : d.source]) :
    src => [for name, d in local.active_detections : name if d.source == src]
  }
}

# Rendered patterns, so you can paste a flow-log pattern into the CloudWatch
# console "Test pattern" box against real log lines.
output "rendered_patterns" {
  value = { for name, d in local.active_detections : name => d.pattern }
}
