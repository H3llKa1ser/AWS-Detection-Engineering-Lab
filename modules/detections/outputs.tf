output "detection_names" {
  value = keys(local.detections)
}

output "detection_count" {
  value = length(local.detections)
}
