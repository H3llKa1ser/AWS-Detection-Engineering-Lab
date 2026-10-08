#!/usr/bin/env bash
# Terraform "external" data source program.
#
# Resolves the region-specific IDs of the AWS-managed DNS Firewall domain lists
# (AWSManagedDomains*) by name, because the AWS provider has no data source that
# looks a domain list up by name and the IDs differ per region.
#
# stdin : {"region": "eu-west-1"}
# stdout: {"AWSManagedDomainsAggregateThreatList": "rslvr-fdl-...", ...}
#
# Needs the AWS CLI v2 with the same credentials Terraform uses (AWS_PROFILE /
# env vars). No jq or python required. Set var.dns_firewall_managed_list_ids
# to skip this script entirely.
set -euo pipefail

input="$(cat)"
region="$(printf '%s' "$input" | sed -n 's/.*"region"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
if [[ -z "$region" ]]; then
  echo "lookup-managed-domain-lists: no region in query" >&2
  exit 1
fi

if ! command -v aws >/dev/null 2>&1; then
  echo "lookup-managed-domain-lists: AWS CLI not found. Install it, or set dns_firewall_managed_list_ids." >&2
  exit 1
fi

# Managed lists are the ones with a ManagedOwnerName. The CLI paginates for us.
rows="$(aws route53resolver list-firewall-domain-lists \
  --region "$region" \
  --query 'FirewallDomainLists[?ManagedOwnerName].[Name,Id]' \
  --output text)"

json="{"
sep=""
while IFS=$'\t' read -r name id; do
  [[ -z "${name:-}" || -z "${id:-}" ]] && continue
  # Names and IDs are [A-Za-z0-9-]; refuse anything else rather than emit bad JSON.
  [[ "$name" =~ ^[A-Za-z0-9-]+$ && "$id" =~ ^[A-Za-z0-9-]+$ ]] || continue
  json+="${sep}\"${name}\":\"${id}\""
  sep=","
done <<< "$rows"
json+="}"

printf '%s\n' "$json"
