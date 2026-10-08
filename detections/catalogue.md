# Detection catalogue

This is generated documentation for the detections defined as code in
[`../modules/detections/catalogue.tf`](../modules/detections/catalogue.tf).
The Terraform map is the source of truth; keep this table in sync when you add
or remove entries.

Each detection is a CloudWatch Logs **metric filter** over the CloudTrail log
group plus a **metric alarm** that notifies the shared SNS topic on the first
match in a 5-minute window.

See the [README detection table](../README.md#detection-catalogue) for the full
CIS + MITRE ATT&CK mapping.

## Tuning notes

- **Thresholds**: all detections alarm at the first event (`threshold = 1`).
  For noisy controls (e.g. `security_group_changes` in an active account) raise
  the threshold or lengthen the period to cut false positives.
- **Suppression**: legitimate automation (Terraform, CI roles) will trip
  control-plane detections. Prefer filtering by `userIdentity.arn` in the metric
  filter pattern over disabling the detection.
- **Coverage gaps**: metric filters only see what CloudTrail logs. Data-plane
  events (S3 object access, Lambda invokes) require CloudTrail data events, which
  are not enabled here by default for cost reasons.
