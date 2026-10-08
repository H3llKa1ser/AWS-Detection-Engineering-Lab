# ---------------------------------------------------------------------------
# Route 53 Resolver DNS Firewall: block, not just detect.
#
# One rule group, evaluated in priority order (lowest first, first match wins):
#
#   100        ALLOW  custom allow list   (false-positive overrides)
#   200        BLOCK  custom block list   (domains you never want resolved)
#   300, 310.. per-list action on each AWS-managed threat list, in the order given
#   400, 410.. DNS Firewall Advanced: DGA / dictionary DGA / tunnelling detectors
#              (no domain list; ALERT or BLOCK only, ALLOW is not supported)
#
# The allow list at 100 therefore also overrides Advanced false positives,
# which is the remediation AWS documents for them.
#
# The rule group is associated with every protected VPC, and each VPC gets an
# explicit fail-open / fail-closed setting. Every match on an ALERT or BLOCK
# rule is written into the Resolver query logs (firewall_rule_action,
# firewall_domain_list_id), which is what the dns_firewall_* detections read.
# ---------------------------------------------------------------------------

locals {
  # Apex + wildcard: "*.example.com" alone does not match "example.com".
  expand = { for kind, domains in { allow = var.allow_domains, block = var.block_domains } :
    kind => distinct(flatten([for d in domains : [lower(trimsuffix(d, ".")), "*.${lower(trimsuffix(d, "."))}"]]))
  }

  managed = { for i, l in var.managed_domain_lists : l.name => {
    action   = upper(l.action)
    priority = 300 + i * 10
  } }

  advanced = { for i, a in var.advanced_protections : upper(a.protection) => {
    action     = upper(a.action)
    confidence = upper(a.confidence)
    priority   = 400 + i * 10
  } }

  # Look up only the lists that were not supplied as overrides.
  need_lookup = length(setsubtract(keys(local.managed), keys(var.managed_domain_list_ids))) > 0

  managed_ids = merge(
    try(data.external.managed_lists[0].result, {}),
    var.managed_domain_list_ids,
  )
}

# --- Resolve AWS-managed list IDs (they differ per region) -----------------
data "external" "managed_lists" {
  count   = local.need_lookup ? 1 : 0
  program = ["bash", "${path.module}/scripts/lookup-managed-domain-lists.sh"]
  query   = { region = var.region }
}

# Read each managed list through the provider, and refuse to continue unless
# it exists in this region and really is AWS-managed.
data "aws_route53_resolver_firewall_domain_list" "managed" {
  for_each = local.managed

  firewall_domain_list_id = lookup(local.managed_ids, each.key, "rslvr-fdl-missing")

  lifecycle {
    precondition {
      condition     = contains(keys(local.managed_ids), each.key)
      error_message = "Managed domain list ${each.key} was not found in ${var.region}. Check the name, or supply its id in dns_firewall_managed_list_ids."
    }
    postcondition {
      condition     = self.name == each.key && self.managed_owner_name != ""
      error_message = "Domain list ${self.firewall_domain_list_id} is not the AWS-managed list ${each.key}."
    }
  }
}

# --- Custom lists -------------------------------------------------------------
resource "aws_route53_resolver_firewall_domain_list" "allow" {
  count   = length(local.expand.allow) > 0 ? 1 : 0
  name    = "${var.name_prefix}-allowlist"
  domains = local.expand.allow
}

resource "aws_route53_resolver_firewall_domain_list" "block" {
  count   = length(local.expand.block) > 0 ? 1 : 0
  name    = "${var.name_prefix}-blocklist"
  domains = local.expand.block
}

# --- Rule group and rules -------------------------------------------------------
resource "aws_route53_resolver_firewall_rule_group" "main" {
  name = "${var.name_prefix}-dns-firewall"
}

resource "aws_route53_resolver_firewall_rule" "allow" {
  count                   = length(aws_route53_resolver_firewall_domain_list.allow)
  name                    = "${var.name_prefix}-allow-overrides"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.main.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.allow[0].id
  priority                = 100
  action                  = "ALLOW"
}

resource "aws_route53_resolver_firewall_rule" "block" {
  count                   = length(aws_route53_resolver_firewall_domain_list.block)
  name                    = "${var.name_prefix}-block-custom"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.main.id
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.block[0].id
  priority                = 200
  action                  = "BLOCK"

  block_response          = var.block_response
  block_override_domain   = var.block_response == "OVERRIDE" ? var.block_override_domain : null
  block_override_dns_type = var.block_response == "OVERRIDE" ? "CNAME" : null
  block_override_ttl      = var.block_response == "OVERRIDE" ? 60 : null
}

resource "aws_route53_resolver_firewall_rule" "managed" {
  for_each = local.managed

  name                    = "${var.name_prefix}-${lower(each.value.action)}-${each.key}"
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.main.id
  firewall_domain_list_id = data.aws_route53_resolver_firewall_domain_list.managed[each.key].firewall_domain_list_id
  priority                = each.value.priority
  action                  = each.value.action

  # Block-response settings are only valid on BLOCK rules.
  block_response          = each.value.action == "BLOCK" ? var.block_response : null
  block_override_domain   = each.value.action == "BLOCK" && var.block_response == "OVERRIDE" ? var.block_override_domain : null
  block_override_dns_type = each.value.action == "BLOCK" && var.block_response == "OVERRIDE" ? "CNAME" : null
  block_override_ttl      = each.value.action == "BLOCK" && var.block_response == "OVERRIDE" ? 60 : null
}

# DNS Firewall Advanced: behavioural detectors instead of domain lists.
resource "aws_route53_resolver_firewall_rule" "advanced" {
  for_each = local.advanced

  name                   = "${var.name_prefix}-${lower(each.value.action)}-advanced-${lower(replace(each.key, "_", "-"))}"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.main.id
  priority               = each.value.priority
  action                 = each.value.action
  dns_threat_protection  = each.key
  confidence_threshold   = each.value.confidence

  block_response          = each.value.action == "BLOCK" ? var.block_response : null
  block_override_domain   = each.value.action == "BLOCK" && var.block_response == "OVERRIDE" ? var.block_override_domain : null
  block_override_dns_type = each.value.action == "BLOCK" && var.block_response == "OVERRIDE" ? "CNAME" : null
  block_override_ttl      = each.value.action == "BLOCK" && var.block_response == "OVERRIDE" ? 60 : null
}

# --- Attach to VPCs -------------------------------------------------------------
resource "aws_route53_resolver_firewall_rule_group_association" "vpc" {
  for_each = var.vpc_ids

  name                   = "${var.name_prefix}-dns-firewall-${each.key}"
  firewall_rule_group_id = aws_route53_resolver_firewall_rule_group.main.id
  vpc_id                 = each.value
  priority               = var.association_priority
  mutation_protection    = "DISABLED" # set ENABLED in production to stop out-of-band changes

  # Associate only once every rule exists, so a VPC never runs a partial policy.
  depends_on = [
    aws_route53_resolver_firewall_rule.allow,
    aws_route53_resolver_firewall_rule.block,
    aws_route53_resolver_firewall_rule.managed,
    aws_route53_resolver_firewall_rule.advanced,
  ]
}

resource "aws_route53_resolver_firewall_config" "vpc" {
  for_each = var.vpc_ids

  resource_id        = each.value
  firewall_fail_open = var.fail_open ? "ENABLED" : "DISABLED"
}

# ---------------------------------------------------------------------------
# Advanced verdict alerting via EventBridge
#
# Query logs show THAT a query was blocked; only DNS Firewall's EventBridge
# events document WHICH Advanced detector fired (detail.firewall-protection).
# DNS Firewall sends them to the default bus automatically, at most once per
# domain per 6 hours, so every event is a newly flagged name.
#
# Per enabled protection: one rule -> evidence log group (raw events for
# triage) and one alarm on the rule's MatchedEvents metric -> SNS. Alarming on
# the metric gives one notification per 5-minute window instead of one email
# per flagged name, which matters for tunnelling (every query is a new name).
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "advanced_events" {
  count             = length(local.advanced) > 0 ? 1 : 0
  name              = "/aws/events/${var.name_prefix}-dns-firewall-advanced"
  retention_in_days = var.event_log_retention_days
  kms_key_id        = var.kms_key_arn
}

resource "aws_cloudwatch_event_rule" "advanced" {
  for_each = local.advanced

  name        = "${var.name_prefix}-dnsfw-${lower(replace(each.key, "_", "-"))}"
  description = "DNS Firewall Advanced ${each.key} verdicts (ALERT and BLOCK)."
  event_pattern = jsonencode({
    source      = ["aws.route53resolver"]
    detail-type = ["DNS Firewall Block", "DNS Firewall Alert"]
    detail = {
      firewall-protection = [each.key]
    }
  })
}

resource "aws_cloudwatch_event_target" "advanced" {
  for_each = local.advanced

  rule      = aws_cloudwatch_event_rule.advanced[each.key].name
  target_id = "evidence-log"
  arn       = aws_cloudwatch_log_group.advanced_events[0].arn
}

# EventBridge needs a resource policy to write into a log group.
data "aws_iam_policy_document" "advanced_events" {
  count = length(local.advanced) > 0 ? 1 : 0

  statement {
    sid       = "EventBridgeCreateStream"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream"]
    resources = ["${aws_cloudwatch_log_group.advanced_events[0].arn}:*"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "delivery.logs.amazonaws.com"]
    }
  }
  statement {
    sid       = "EventBridgePutEvents"
    effect    = "Allow"
    actions   = ["logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.advanced_events[0].arn}:*:*"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "delivery.logs.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [for r in aws_cloudwatch_event_rule.advanced : r.arn]
    }
  }
}

resource "aws_cloudwatch_log_resource_policy" "advanced_events" {
  count           = length(local.advanced) > 0 ? 1 : 0
  policy_name     = "${var.name_prefix}-dns-firewall-advanced-events"
  policy_document = data.aws_iam_policy_document.advanced_events[0].json
}

locals {
  advanced_attack = {
    DGA            = "T1568.002 Dynamic Resolution: Domain Generation Algorithms"
    DICTIONARY_DGA = "T1568.002 Dynamic Resolution: Domain Generation Algorithms (dictionary)"
    DNS_TUNNELING  = "T1071.004 Application Layer Protocol: DNS / T1048 Exfiltration"
  }
}

resource "aws_cloudwatch_metric_alarm" "advanced" {
  for_each = local.advanced

  alarm_name          = "${var.name_prefix}-dns_firewall_advanced_${lower(each.key)}"
  alarm_description   = "[dns_firewall_advanced] DNS Firewall Advanced ${each.key} (${each.value.action} @ ${each.value.confidence}) flagged new names | ATT&CK: ${lookup(local.advanced_attack, each.key, "T1071.004")}"
  namespace           = "AWS/Events"
  metric_name         = "MatchedEvents"
  dimensions          = { RuleName = aws_cloudwatch_event_rule.advanced[each.key].name }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = var.advanced_alarm_threshold
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching" # EventBridge publishes the metric only when non-zero

  alarm_actions = [var.alert_topic_arn]
  ok_actions    = [var.alert_topic_arn]

  tags = {
    attack_technique = lookup(local.advanced_attack, each.key, "T1071.004")
    telemetry_source = "dns_firewall_advanced"
  }
}
