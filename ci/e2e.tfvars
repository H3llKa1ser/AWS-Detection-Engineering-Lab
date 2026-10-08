# Settings for the live end-to-end tier (.github/workflows/live.yml).
# name_prefix is set per run (e2e-<run id>-<attempt>), so runs never collide.

# Account-level singletons: one per account and region. Off by default so the
# sandbox can already have them (e.g. enabled by an organization) without the
# apply failing, and because enabling/disabling them is slow. Not covered by e2e.
enable_guardduty   = false
enable_securityhub = false
enable_config      = false

# Everything the e2e tier exercises.
kms_encrypt_logs           = true
enable_vpc_flow_logs       = true
enable_dns_query_logging   = true
enable_dns_firewall        = true
enable_network_log_lake    = true
enable_threat_hunting      = true
enable_threat_intel        = true
enable_scheduled_hunts     = true
enable_sigma               = true
retro_hunt_on_intel_change = true
deploy_traffic_generator   = true # DNS for the DNS, DNS Firewall, lake and intel checks
enable_response_automation = false

# Alerts go to an SQS queue the harness subscribes; no email.
alert_email = ""

# Short-lived data.
log_retention_days          = 1
network_log_retention_days  = 1
network_lake_retention_days = 1
